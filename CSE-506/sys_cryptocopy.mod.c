#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xbd04df57, "module_layout" },
	{ 0x1d47defc, "sysptr" },
	{ 0xd36740f8, "vfs_unlink" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xcd286050, "vfs_rename" },
	{ 0xe2e156b2, "filp_close" },
	{ 0x754d539c, "strlen" },
	{ 0x41c2504c, "filp_open" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xfef8cf74, "vfs_statx" },
	{ 0xb2be2bd6, "getname" },
	{ 0x37a0cba, "kfree" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xc741778, "current_task" },
	{ 0x1e0451d5, "kmem_cache_alloc_trace" },
	{ 0x7ff874a4, "kmalloc_caches" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x6de13801, "wait_for_completion" },
	{ 0x54b63f4d, "crypto_skcipher_encrypt" },
	{ 0x7a4497db, "kzfree" },
	{ 0x30c8192e, "crypto_destroy_tfm" },
	{ 0x73d86fac, "crypto_skcipher_decrypt" },
	{ 0xd9a5ea54, "__init_waitqueue_head" },
	{ 0xb320cc0e, "sg_init_one" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0x24230ce6, "crypto_req_done" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x4349d2ce, "crypto_alloc_skcipher" },
	{ 0xacb676ca, "vfs_write" },
	{ 0x5562ab9d, "vfs_read" },
	{ 0xc5850110, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "1E63A7FB96D3FA2B69A80B1");
