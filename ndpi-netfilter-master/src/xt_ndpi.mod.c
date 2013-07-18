#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2bf4f620, "module_layout" },
	{ 0xe2fc3a6, "kmem_cache_destroy" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0x754d539c, "strlen" },
	{ 0x78f9b710, "nf_ct_l3proto_try_module_get" },
	{ 0x1637ff0f, "_raw_spin_lock_bh" },
	{ 0xa6d63018, "skb_copy" },
	{ 0xfbe27a1c, "rb_first" },
	{ 0xfb578fc5, "memset" },
	{ 0x27e1a049, "printk" },
	{ 0x449ad0a7, "memcmp" },
	{ 0xc0580937, "rb_erase" },
	{ 0x9166fada, "strncpy" },
	{ 0xb4390f9a, "mcount" },
	{ 0x5a921311, "strncmp" },
	{ 0xbf8ba54a, "vprintk" },
	{ 0x8391573e, "kmem_cache_free" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0xa07a37f0, "memchr" },
	{ 0x26bba3b9, "init_net" },
	{ 0xe2bb5e9e, "kmem_cache_alloc" },
	{ 0xba63339c, "_raw_spin_unlock_bh" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xae50fe36, "kfree_skb" },
	{ 0xd7e90319, "xt_unregister_match" },
	{ 0x586705f7, "nf_conntrack_unregister_notifier" },
	{ 0xa6dcc773, "rb_insert_color" },
	{ 0xa6e90b2d, "kmem_cache_create" },
	{ 0x4f68e5c9, "do_gettimeofday" },
	{ 0xb602c57e, "nf_ct_l3proto_module_put" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xb81daabe, "nf_conntrack_untracked" },
	{ 0xbdf5c25c, "rb_next" },
	{ 0x7f36a804, "xt_register_match" },
	{ 0xf17529af, "nf_conntrack_register_notifier" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=nf_conntrack,x_tables";


MODULE_INFO(srcversion, "28E8FA6A1C7322006857F08");
