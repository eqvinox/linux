/*
 *  net/mpls/vpls.c
 *
 *  Copyright (C) 2016 David Lamparter
 *
 */

#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/mpls.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/mpls.h>
#include <linux/module.h>
#include <net/dst_metadata.h>
#include <net/ip_tunnels.h>
#include <linux/lwtunnel.h>
#include <linux/skbpunt.h>

#include "internal.h"

#define DRV_NAME	"vpls"

#define MIN_MTU 68		/* Min L3 MTU */
#define MAX_MTU 65535		/* Max L3 MTU (arbitrary) */

struct vpls_cw {
	/* lower nibble indicates packet type, 0000 for normal packets.
	 * (also used to distinguish from no-CW IPv4/IPv6 MPLS encapsulation,
	 * otherwise strange things happen for ?4:... and ?6:... MAC addr)
	 *
	 * everything else is OAM of some type and shouldn't be naively
	 * decapsulated as ethernet
	 */
	u8 type_flags;
#define VPLS_CWTYPE(cw) ((cw)->type_flags & 0x0f)

	u8 len;
	u16 seqno;
};

struct vpls_wirelist {
	struct rcu_head rcu;
	size_t count;
	unsigned wires[0];
};

struct vpls_priv {
	struct net *encap_net;
	struct vpls_wirelist __rcu *wires;

	u8 ttl;
};

/* vpls ifindex passed as u32; skb interface is MPLS ingress iface */
static struct skbpunt_location vpls_oam_punt __read_mostly = {
	.owner = THIS_MODULE,
	.name = "vplsoam\0",
	.infocuts = { 4, 0 },
};

static struct skbpunt_location vpls_cw_punt __read_mostly = {
	.owner = THIS_MODULE,
	.name = "vplscwnz",
	.infocuts = { 4, 0 },
};

static int vpls_xmit_wire(struct sk_buff *skb, struct net_device *dev,
			  struct vpls_priv *vpls, u32 wire)
{
	struct mpls_route *rt;
	struct mpls_entry_decoded dec;

	dec.bos = 1;
	dec.ttl = vpls->ttl;

	rt = mpls_route_input_rcu(vpls->encap_net, wire);
	if (!rt)
		return -ENOENT;
	if (rt->rt_vpls_dev != dev)
		return -EINVAL;

	if (rt->rt_mpls_flags & RTA_MPLS_F_CW_TX) {
		struct vpls_cw *cw;
		if (skb_cow(skb, sizeof(*cw)))
			return -ENOMEM;
		cw = skb_push(skb, sizeof(*cw));
		memset(cw, 0, sizeof(*cw));
	}

	return mpls_rt_xmit(skb, rt, dec);
}

static netdev_tx_t vpls_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int err = -EINVAL, ok_count = 0;
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_info *vi;

	vi = skb_vpls_info(skb);

	skb_orphan(skb);
	skb_forward_csum(skb);

	if (vi) {
		err = vpls_xmit_wire(skb, dev, priv, vi->pw_label);
		if (err)
			goto out_err;
	} else {
		struct sk_buff *cloned;
		struct vpls_wirelist *wl;
		size_t i;

		rcu_read_lock();
		wl = rcu_dereference(priv->wires);
		if (wl->count == 0) {
			dev->stats.tx_carrier_errors++;
			goto out_err_rcu;
		}

		for (i = 0; i < wl->count; i++) {
			cloned = skb_clone(skb, GFP_ATOMIC);
			if (vpls_xmit_wire(cloned, dev, priv, wl->wires[i]))
				consume_skb(cloned);
			else
				ok_count++;
		}
		rcu_read_unlock();

		if (!ok_count)
			goto out_err;
		consume_skb(skb);
	}

	return 0;

out_err_rcu:
	rcu_read_unlock();
out_err:
	dev->stats.tx_errors++;

	consume_skb(skb);
	return err;
}

int vpls_rcv(struct sk_buff *skb, struct net_device *in_dev,
	     struct packet_type *pt, struct mpls_route *rt,
	     struct mpls_shim_hdr *hdr, struct net_device *orig_dev)
{
	struct net_device *dev = rt->rt_vpls_dev;
	struct mpls_entry_decoded dec;
	struct metadata_dst *md_dst;
	void *next;

	if (!dev)
		goto drop_nodev;

	/* bottom label is still in the skb */
	dec = mpls_entry_decode(hdr);
	next = skb_pull(skb, sizeof(*hdr));

	if (!dec.bos) {
		if (unlikely(!pskb_may_pull(skb, sizeof(*hdr)))) {
			dev->stats.rx_frame_errors++;
			goto drop;
		}
		hdr = next;

		dec = mpls_entry_decode(hdr);

		if ((dec.label == MPLS_LABEL_RTALERT ||
		     dec.label == MPLS_LABEL_GAL ||
		     dec.label == MPLS_LABEL_OAMALERT)) {
			u32 ifindex = dev->ifindex;

			if (skb_punt(&vpls_oam_punt, skb, (u8 *)&ifindex,
				     sizeof(ifindex)))
				goto drop_nodev;
		}

		dev->stats.rx_frame_errors++;
		goto drop;
	}

	if (rt->rt_mpls_flags & RTA_MPLS_F_CW_RX) {
		struct vpls_cw *cw = next;
		if (unlikely(!pskb_may_pull(skb, sizeof(*cw)))) {
			dev->stats.rx_length_errors++;
			goto drop;
		}
		next = skb_pull(skb, sizeof(*cw));

		if (VPLS_CWTYPE(cw) != 0) {
			u32 ifindex = dev->ifindex;

			if (skb_punt(&vpls_cw_punt, skb, (u8 *)&ifindex,
				     sizeof(ifindex)))
				goto drop_nodev;

			dev->stats.rx_frame_errors++;
			goto drop;
		}
	}

	if (unlikely(!pskb_may_pull(skb, ETH_HLEN))) {
		dev->stats.rx_length_errors++;
		goto drop;
	}

	md_dst = vpls_rx_dst();
	if (unlikely(!md_dst)) {
		netdev_err(dev, "failed to allocate dst metadata\n");
		goto drop;
	}
	md_dst->u.vpls_info.pw_label = dec.label;

	skb->dev = dev;

	skb_reset_mac_header(skb);
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_HOST;

	skb_clear_hash(skb);
	skb->vlan_tci = 0;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, !net_eq(dev_net(in_dev), dev_net(dev)));

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb);

	skb_dst_drop(skb);
	skb_dst_set(skb, &md_dst->dst);

	netif_rx(skb);
	return 0;

drop:
	dev->stats.rx_errors++;
drop_nodev:
	kfree_skb(skb);
	return NET_RX_DROP;
}

void vpls_label_update(unsigned label, struct mpls_route *rt_old,
		       struct mpls_route *rt_new)
{
	struct vpls_priv *priv;
	struct vpls_wirelist *wl, *wl_new;
	size_t i;

	ASSERT_RTNL();

	if (rt_old && rt_new && rt_old->rt_vpls_dev == rt_new->rt_vpls_dev)
		return;

	if (rt_old && rt_old->rt_vpls_dev) {
		priv = netdev_priv(rt_old->rt_vpls_dev);
		wl = rtnl_dereference(priv->wires);

		for (i = 0; i < wl->count; i++)
			if (wl->wires[i] == label)
				break;

		if (i == wl->count) {
			netdev_err(rt_old->rt_vpls_dev,
				   "can't find pseudowire to remove!\n");
			goto update_new;
		}

		wl_new = kmalloc(sizeof(*wl) +
				 (wl->count - 1) * sizeof(wl->wires[0]),
				 GFP_ATOMIC);
		if (!wl_new) {
			netdev_err(rt_old->rt_vpls_dev,
				   "out of memory for pseudowire delete!\n");
			goto update_new;
		}

		wl_new->count = wl->count - 1;
		memcpy(wl_new->wires, wl->wires, i * sizeof(wl->wires[0]));
		memcpy(wl_new->wires + i, wl->wires + i + 1,
			(wl->count - i - 1) * sizeof(wl->wires[0]));

		rcu_assign_pointer(priv->wires, wl_new);
		kfree_rcu(wl, rcu);

		if (wl_new->count == 0)
			netif_carrier_off(rt_old->rt_vpls_dev);
	}

update_new:
	if (rt_new && rt_new->rt_vpls_dev) {
		priv = netdev_priv(rt_new->rt_vpls_dev);
		wl = rtnl_dereference(priv->wires);

		wl_new = kmalloc(sizeof(*wl) +
				 (wl->count + 1) * sizeof(wl->wires[0]),
				 GFP_ATOMIC);
		if (!wl_new) {
			netdev_err(rt_new->rt_vpls_dev,
				   "out of memory for pseudowire add!\n");
			return;
		}
		wl_new->count = wl->count + 1;
		memcpy(wl_new->wires, wl->wires,
			wl->count * sizeof(wl->wires[0]));
		wl_new->wires[wl->count] = label;

		rcu_assign_pointer(priv->wires, wl_new);
		kfree_rcu(wl, rcu);

		if (wl_new->count == 1)
			netif_carrier_on(rt_new->rt_vpls_dev);
	}
}

/* fake multicast ability */
static void vpls_set_multicast_list(struct net_device *dev)
{
}

static int vpls_open(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	struct vpls_wirelist *wl;

	wl = rtnl_dereference(priv->wires);
	if (wl->count > 0)
		netif_carrier_on(dev);

	return 0;
}

static int vpls_close(struct net_device *dev)
{
	netif_carrier_off(dev);
	return 0;
}

static int is_valid_vpls_mtu(int new_mtu)
{
	return new_mtu >= MIN_MTU && new_mtu <= MAX_MTU;
}

static int vpls_change_mtu(struct net_device *dev, int new_mtu)
{
	if (!is_valid_vpls_mtu(new_mtu))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static int vpls_dev_init(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);
	priv->wires = kzalloc(sizeof(struct vpls_wirelist), GFP_KERNEL);
	if (!priv->wires)
		return -ENOMEM;

	priv->ttl = 255;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats) {
		kfree(priv->wires);
		return -ENOMEM;
	}

	return 0;
}

static void vpls_dev_free(struct net_device *dev)
{
	struct vpls_priv *priv = netdev_priv(dev);

	free_percpu(dev->tstats);

	if (priv->wires)
		kfree(priv->wires);

	if (priv->encap_net)
		put_net(priv->encap_net);

	free_netdev(dev);
}

static const struct nla_policy vpls_meta_policy[LWT_PSEUDOWIRE_MAX + 1] = {
	[LWT_PSEUDOWIRE_LOCAL_LABEL]	= { .type = NLA_U32 },
};

static int vpls_fill_metadst(struct sk_buff *skb, struct metadata_dst *md_dst)
{
	struct vpls_info *vi;
	if (md_dst->type != METADATA_VPLS)
		return 0;

	vi = &md_dst->u.vpls_info;
	if (nla_put_u32(skb, LWT_PSEUDOWIRE_LOCAL_LABEL, vi->pw_label))
		return -ENOMEM;
	return LWTUNNEL_ENCAP_PSEUDOWIRE;
}

static int vpls_build_metadst(struct net_device *dev, struct nlattr *meta,
			      struct metadata_dst **dst,
			      struct netlink_ext_ack *extack)
{
	struct nlattr *tb[LWT_PSEUDOWIRE_MAX + 1];
	struct metadata_dst *rv;
	int err;
	unsigned wire;

	err = nla_parse_nested(tb, LWT_PSEUDOWIRE_MAX, meta,
			       vpls_meta_policy, extack);
	if (err < 0)
		return err;

	if (!tb[LWT_PSEUDOWIRE_LOCAL_LABEL])
		return -EINVAL;
	wire = nla_get_u32(tb[LWT_PSEUDOWIRE_LOCAL_LABEL]);
	if (wire < MPLS_LABEL_FIRST_UNRESERVED)
		return -EINVAL;

	rv = vpls_rx_dst();
	if (!rv)
		return -ENOMEM;
	rv->u.vpls_info.pw_label = wire;

	*dst = rv;
	return 0;
}

static const struct net_device_ops vpls_netdev_ops = {
	.ndo_init		= vpls_dev_init,
	.ndo_open		= vpls_open,
	.ndo_stop		= vpls_close,
	.ndo_start_xmit		= vpls_xmit,
	.ndo_change_mtu		= vpls_change_mtu,
	.ndo_get_stats64	= dev_get_tstats64,
	.ndo_set_rx_mode	= vpls_set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_features_check	= passthru_features_check,
	.ndo_metadst_fill	= vpls_fill_metadst,
	.ndo_metadst_build	= vpls_build_metadst,
};

int is_vpls_dev(struct net_device *dev)
{
	return dev->netdev_ops == &vpls_netdev_ops;
}

#define VPLS_FEATURES (NETIF_F_SG | NETIF_F_FRAGLIST | \
		       NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_HIGHDMA)

static void vpls_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_NO_QUEUE;

	dev->netdev_ops = &vpls_netdev_ops;
	dev->features |= VPLS_FEATURES;
	dev->vlan_features = dev->features;
	dev->priv_destructor = vpls_dev_free;

	dev->hw_features = VPLS_FEATURES;
	dev->hw_enc_features = VPLS_FEATURES;

	dev->lltx = true;

	netif_keep_dst(dev);
}

/*
 * netlink interface
 */

static int vpls_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
				    "Invalid Ethernet address length");
			return -EINVAL;
		}
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_ADDRESS],
				    "Invalid Ethernet address");
			return -EADDRNOTAVAIL;
		}
	}
	if (tb[IFLA_MTU]) {
		if (!is_valid_vpls_mtu(nla_get_u32(tb[IFLA_MTU]))) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_MTU],
				    "Invalid MTU");
			return -EINVAL;
		}
	}
	return 0;
}

static struct rtnl_link_ops vpls_link_ops;

static int vpls_newlink(struct net_device *dev,
			struct rtnl_newlink_params *params,
			struct netlink_ext_ack *extack)
{
	struct nlattr **data = params->data;
	struct nlattr **tb = params->tb;
	int err;
	struct vpls_priv *priv = netdev_priv(dev);

	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strscpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err;
	priv->encap_net = get_net(params->src_net);

	netif_carrier_off(dev);
	return 0;

err:
	return err;
}

static void vpls_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
}


static struct rtnl_link_ops vpls_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct vpls_priv),
	.setup		= vpls_setup,
	.validate	= vpls_validate,
	.newlink	= vpls_newlink,
	.dellink	= vpls_dellink,
};

/*
 * init/fini
 */

__init int vpls_init(void)
{
	int ret;

	ret = rtnl_link_register(&vpls_link_ops);
	if (ret)
		goto out;
	ret = skbpunt_register(&vpls_oam_punt);
	if (ret)
		goto out_remove_link_ops;
	ret = skbpunt_register(&vpls_cw_punt);
	if (ret)
		goto out_remove_vpls_oam;

	return 0;

out_remove_vpls_oam:
	skbpunt_unregister(&vpls_oam_punt);
out_remove_link_ops:
	rtnl_link_unregister(&vpls_link_ops);
out:
	return ret;
}

__exit void vpls_exit(void)
{
	skbpunt_unregister(&vpls_cw_punt);
	skbpunt_unregister(&vpls_oam_punt);
	rtnl_link_unregister(&vpls_link_ops);
}

#if 0
/* not currently available as a separate module... */

module_init(vpls_init);
module_exit(vpls_exit);

MODULE_DESCRIPTION("Virtual Private LAN Service");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
#endif
