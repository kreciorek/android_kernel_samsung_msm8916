/*
 * fs/sysfs/dir.c - sysfs core and dir operation implementation
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 *
 * Please see Documentation/filesystems/sysfs.txt for more information.
 */

#undef DEBUG

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/idr.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/hash.h>
#include "sysfs.h"

DEFINE_SPINLOCK(sysfs_symlink_target_lock);

void sysfs_warn_dup(struct kernfs_node *parent, const char *name)
{
	char *buf;

	buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (buf)
		kernfs_path(parent, buf, PATH_MAX);

	WARN(1, KERN_WARNING "sysfs: cannot create duplicate filename '%s/%s'\n",
	     buf, name);

	kfree(buf);
}

/**
 *	sysfs_remove_one - remove sysfs_dirent from parent
 *	@acxt: addrm context to use
 *	@sd: sysfs_dirent to be removed
 *
 *	Mark @sd removed and drop nlink of parent inode if @sd is a
 *	directory.  @sd is unlinked from the children list.
 *
 *	This function should be called between calls to
 *	sysfs_addrm_start() and sysfs_addrm_finish() and should be
 *	passed the same @acxt as passed to sysfs_addrm_start().
 *
 *	LOCKING:
 *	Determined by sysfs_addrm_start().
 */
void sysfs_remove_one(struct sysfs_addrm_cxt *acxt, struct sysfs_dirent *sd)
{
	struct sysfs_inode_attrs *ps_iattr;

	BUG_ON(sd->s_flags & SYSFS_FLAG_REMOVED);

	sysfs_unlink_sibling(sd);

	/* Update timestamps on the parent */
	ps_iattr = acxt->parent_sd->s_iattr;
	if (ps_iattr) {
		struct iattr *ps_iattrs = &ps_iattr->ia_iattr;
		ps_iattrs->ia_ctime = ps_iattrs->ia_mtime = CURRENT_TIME;
	}

	sd->s_flags |= SYSFS_FLAG_REMOVED;
	sd->u.removed_list = acxt->removed;
	acxt->removed = sd;
}

/**
 *	sysfs_addrm_finish - finish up sysfs_dirent add/remove
 *	@acxt: addrm context to finish up
 *
 *	Finish up sysfs_dirent add/remove.  Resources acquired by
 *	sysfs_addrm_start() are released and removed sysfs_dirents are
 *	cleaned up.
 *
 *	LOCKING:
 *	sysfs_mutex is released.
 */
void sysfs_addrm_finish(struct sysfs_addrm_cxt *acxt)
{
	/* release resources acquired by sysfs_addrm_start() */
	mutex_unlock(&sysfs_mutex);

	/* kill removed sysfs_dirents */
	while (acxt->removed) {
		struct sysfs_dirent *sd = acxt->removed;

		acxt->removed = sd->u.removed_list;

		sysfs_deactivate(sd);
		unmap_bin_file(sd);
		sysfs_put(sd);
	}
}

/**
 *	sysfs_find_dirent - find sysfs_dirent with the given name
 *	@parent_sd: sysfs_dirent to search under
 *	@name: name to look for
 *
 *	Look for sysfs_dirent with name @name under @parent_sd.
 *
 *	LOCKING:
 *	mutex_lock(sysfs_mutex)
 *
 *	RETURNS:
 *	Pointer to sysfs_dirent if found, NULL if not.
 */
struct sysfs_dirent *sysfs_find_dirent(struct sysfs_dirent *parent_sd,
				       const void *ns,
				       const unsigned char *name)
{
	struct rb_node *node = parent_sd->s_dir.children.rb_node;
	unsigned int hash;

	if (!!sysfs_ns_type(parent_sd) != !!ns) {
		WARN(1, KERN_WARNING "sysfs: ns %s in '%s' for '%s'\n",
			sysfs_ns_type(parent_sd)? "required": "invalid",
			parent_sd->s_name, name);
		return NULL;
	}

	hash = sysfs_name_hash(ns, name);
	while (node) {
		struct sysfs_dirent *sd;
		int result;

		sd = to_sysfs_dirent(node);
		result = sysfs_name_compare(hash, ns, name, sd);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return sd;
	}
	return NULL;
}

/**
 *	sysfs_get_dirent - find and get sysfs_dirent with the given name
 *	@parent_sd: sysfs_dirent to search under
 *	@name: name to look for
 *
 *	Look for sysfs_dirent with name @name under @parent_sd and get
 *	it if found.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep).  Grabs sysfs_mutex.
 *
 *	RETURNS:
 *	Pointer to sysfs_dirent if found, NULL if not.
 */
struct sysfs_dirent *sysfs_get_dirent(struct sysfs_dirent *parent_sd,
				      const void *ns,
				      const unsigned char *name)
{
	struct sysfs_dirent *sd;

	mutex_lock(&sysfs_mutex);
	sd = sysfs_find_dirent(parent_sd, ns, name);
	sysfs_get(sd);
	mutex_unlock(&sysfs_mutex);

	return sd;
}
EXPORT_SYMBOL_GPL(sysfs_get_dirent);

static int create_dir(struct kobject *kobj, struct sysfs_dirent *parent_sd,
	enum kobj_ns_type type, const void *ns, const char *name,
	struct sysfs_dirent **p_sd)
{
	umode_t mode = S_IFDIR| S_IRWXU | S_IRUGO | S_IXUGO;
	struct sysfs_addrm_cxt acxt;
	struct sysfs_dirent *sd;
	int rc;

	/* allocate */
	sd = sysfs_new_dirent(name, mode, SYSFS_DIR);
	if (!sd)
		return -ENOMEM;

	sd->s_flags |= (type << SYSFS_NS_TYPE_SHIFT);
	sd->s_ns = ns;
	sd->s_dir.kobj = kobj;

	/* link in */
	sysfs_addrm_start(&acxt, parent_sd);
	rc = sysfs_add_one(&acxt, sd);
	sysfs_addrm_finish(&acxt);

	if (rc == 0)
		*p_sd = sd;
	else
		sysfs_put(sd);

	return rc;
}

int sysfs_create_subdir(struct kobject *kobj, const char *name,
			struct sysfs_dirent **p_sd)
{
	return create_dir(kobj, kobj->sd,
			  KOBJ_NS_TYPE_NONE, NULL, name, p_sd);
}

/**
 *	sysfs_read_ns_type: return associated ns_type
 *	@kobj: the kobject being queried
 *
 *	Each kobject can be tagged with exactly one namespace type
 *	(i.e. network or user).  Return the ns_type associated with
 *	this object if any
 */
static enum kobj_ns_type sysfs_read_ns_type(struct kobject *kobj)
{
	const struct kobj_ns_type_operations *ops;
	enum kobj_ns_type type;

	ops = kobj_child_ns_ops(kobj);
	if (!ops)
		return KOBJ_NS_TYPE_NONE;

	type = ops->type;
	BUG_ON(type <= KOBJ_NS_TYPE_NONE);
	BUG_ON(type >= KOBJ_NS_TYPES);
	BUG_ON(!kobj_ns_type_registered(type));

	return type;
}

/**
 *	sysfs_create_dir - create a directory for an object.
 *	@kobj:		object we're creating directory for. 
 */
int sysfs_create_dir(struct kobject * kobj)
{
	enum kobj_ns_type type;
	struct sysfs_dirent *parent_sd, *sd;
	const void *ns = NULL;
	int error = 0;

	BUG_ON(!kobj);

	if (kobj->parent)
		parent_sd = kobj->parent->sd;
	else
		parent_sd = &sysfs_root;

	if (!parent_sd)
		return -ENOENT;

	if (sysfs_ns_type(parent_sd))
		ns = kobj->ktype->namespace(kobj);
	type = sysfs_read_ns_type(kobj);

	error = create_dir(kobj, parent_sd, type, ns, kobject_name(kobj), &sd);
	if (!error)
		kobj->sd = sd;
	return error;
}

static struct dentry * sysfs_lookup(struct inode *dir, struct dentry *dentry,
				unsigned int flags)
{
	struct dentry *ret = NULL;
	struct dentry *parent = dentry->d_parent;
	struct sysfs_dirent *parent_sd = parent->d_fsdata;
	struct sysfs_dirent *sd;
	struct inode *inode;
	enum kobj_ns_type type;
	const void *ns;

	mutex_lock(&sysfs_mutex);

	type = sysfs_ns_type(parent_sd);
	ns = sysfs_info(dir->i_sb)->ns[type];

	sd = sysfs_find_dirent(parent_sd, ns, dentry->d_name.name);

	/* no such entry */
	if (!sd) {
		ret = ERR_PTR(-ENOENT);
		goto out_unlock;
	}
	dentry->d_fsdata = sysfs_get(sd);

	/* attach dentry and inode */
	inode = sysfs_get_inode(dir->i_sb, sd);
	if (!inode) {
		ret = ERR_PTR(-ENOMEM);
		goto out_unlock;
	}

	/* instantiate and hash dentry */
	ret = d_materialise_unique(dentry, inode);
 out_unlock:
	mutex_unlock(&sysfs_mutex);
	return ret;
}

const struct inode_operations sysfs_dir_inode_operations = {
	.lookup		= sysfs_lookup,
	.permission	= sysfs_permission,
	.setattr	= sysfs_setattr,
	.getattr	= sysfs_getattr,
	.setxattr	= sysfs_setxattr,
};

static void remove_dir(struct sysfs_dirent *sd)
{
	struct sysfs_addrm_cxt acxt;

	sysfs_addrm_start(&acxt, sd->s_parent);
	sysfs_remove_one(&acxt, sd);
	sysfs_addrm_finish(&acxt);
}

void sysfs_remove_subdir(struct sysfs_dirent *sd)
{
	remove_dir(sd);
}


static void __sysfs_remove_dir(struct sysfs_dirent *dir_sd)
{
	struct sysfs_addrm_cxt acxt;
	struct rb_node *pos;

	if (!dir_sd)
		return;

	pr_debug("sysfs %s: removing dir\n", dir_sd->s_name);
	sysfs_addrm_start(&acxt, dir_sd);
	pos = rb_first(&dir_sd->s_dir.children);
	while (pos) {
		struct sysfs_dirent *sd = to_sysfs_dirent(pos);
		pos = rb_next(pos);
		if (sysfs_type(sd) != SYSFS_DIR)
			sysfs_remove_one(&acxt, sd);
	}
	sysfs_addrm_finish(&acxt);

	remove_dir(dir_sd);
}

/**
 *	sysfs_remove_dir - remove an object's directory.
 *	@kobj:	object.
 *
 *	The only thing special about this is that we remove any files in
 *	the directory before we remove the directory, and we've inlined
 *	what used to be sysfs_rmdir() below, instead of calling separately.
 */

void sysfs_remove_dir(struct kobject * kobj)
{
	struct sysfs_dirent *sd = kobj->sd;

	spin_lock(&sysfs_assoc_lock);
	kobj->sd = NULL;
	spin_unlock(&sysfs_assoc_lock);

	__sysfs_remove_dir(sd);
}

int sysfs_rename(struct sysfs_dirent *sd,
	struct sysfs_dirent *new_parent_sd, const void *new_ns,
	const char *new_name)
{
	int error;

	mutex_lock(&sysfs_mutex);

	error = 0;
	if ((sd->s_parent == new_parent_sd) && (sd->s_ns == new_ns) &&
	    (strcmp(sd->s_name, new_name) == 0))
		goto out;	/* nothing to rename */

	error = -EEXIST;
	if (sysfs_find_dirent(new_parent_sd, new_ns, new_name))
		goto out;

	/* rename sysfs_dirent */
	if (strcmp(sd->s_name, new_name) != 0) {
		error = -ENOMEM;
		new_name = kstrdup(new_name, GFP_KERNEL);
		if (!new_name)
			goto out;

		kfree(sd->s_name);
		sd->s_name = new_name;
	}

	/* Move to the appropriate place in the appropriate directories rbtree. */
	sysfs_unlink_sibling(sd);
	sysfs_get(new_parent_sd);
	sysfs_put(sd->s_parent);
	sd->s_ns = new_ns;
	sd->s_hash = sysfs_name_hash(sd->s_ns, sd->s_name);
	sd->s_parent = new_parent_sd;
	sysfs_link_sibling(sd);

	error = 0;
 out:
	mutex_unlock(&sysfs_mutex);
	return error;
}

int sysfs_rename_dir(struct kobject *kobj, const char *new_name)
{
	struct sysfs_dirent *parent_sd = kobj->sd->s_parent;
	const void *new_ns = NULL;

	if (sysfs_ns_type(parent_sd))
		new_ns = kobj->ktype->namespace(kobj);

	return sysfs_rename(kobj->sd, parent_sd, new_ns, new_name);
}

int sysfs_move_dir(struct kobject *kobj, struct kobject *new_parent_kobj)
{
	struct sysfs_dirent *sd = kobj->sd;
	struct sysfs_dirent *new_parent_sd;
	const void *new_ns = NULL;

	BUG_ON(!sd->s_parent);
	if (sysfs_ns_type(sd->s_parent))
		new_ns = kobj->ktype->namespace(kobj);
	new_parent_sd = new_parent_kobj && new_parent_kobj->sd ?
		new_parent_kobj->sd : &sysfs_root;

	return sysfs_rename(sd, new_parent_sd, new_ns, sd->s_name);
}

/* Relationship between s_mode and the DT_xxx types */
static inline unsigned char dt_type(struct sysfs_dirent *sd)
{
	return (sd->s_mode >> 12) & 15;
}

static int sysfs_dir_release(struct inode *inode, struct file *filp)
{
	sysfs_put(filp->private_data);
	return 0;
}

static struct sysfs_dirent *sysfs_dir_pos(const void *ns,
	struct sysfs_dirent *parent_sd,	loff_t hash, struct sysfs_dirent *pos)
{
	if (pos) {
		int valid = !(pos->s_flags & SYSFS_FLAG_REMOVED) &&
			pos->s_parent == parent_sd &&
			hash == pos->s_hash;
		sysfs_put(pos);
		if (!valid)
			pos = NULL;
	}
	if (!pos && (hash > 1) && (hash < INT_MAX)) {
		struct rb_node *node = parent_sd->s_dir.children.rb_node;
		while (node) {
			pos = to_sysfs_dirent(node);

			if (hash < pos->s_hash)
				node = node->rb_left;
			else if (hash > pos->s_hash)
				node = node->rb_right;
			else
				break;
		}
	}
	/* Skip over entries in the wrong namespace */
	while (pos && pos->s_ns != ns) {
		struct rb_node *node = rb_next(&pos->s_rb);
		if (!node)
			pos = NULL;
		else
			pos = to_sysfs_dirent(node);
	}
	return pos;
}

static struct sysfs_dirent *sysfs_dir_next_pos(const void *ns,
	struct sysfs_dirent *parent_sd,	ino_t ino, struct sysfs_dirent *pos)
{
	pos = sysfs_dir_pos(ns, parent_sd, ino, pos);
	if (pos) do {
		struct rb_node *node = rb_next(&pos->s_rb);
		if (!node)
			pos = NULL;
		else
			pos = to_sysfs_dirent(node);
	} while (pos && pos->s_ns != ns);
	return pos;
}

static int sysfs_readdir(struct file * filp, void * dirent, filldir_t filldir)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct sysfs_dirent * parent_sd = dentry->d_fsdata;
	struct sysfs_dirent *pos = filp->private_data;
	enum kobj_ns_type type;
	const void *ns;
	ino_t ino;
	loff_t off;

	type = sysfs_ns_type(parent_sd);
	ns = sysfs_info(dentry->d_sb)->ns[type];

	if (filp->f_pos == 0) {
		ino = parent_sd->s_ino;
		if (filldir(dirent, ".", 1, filp->f_pos, ino, DT_DIR) == 0)
			filp->f_pos++;
		else
			return 0;
	}
	if (filp->f_pos == 1) {
		if (parent_sd->s_parent)
			ino = parent_sd->s_parent->s_ino;
		else
			ino = parent_sd->s_ino;
		if (filldir(dirent, "..", 2, filp->f_pos, ino, DT_DIR) == 0)
			filp->f_pos++;
		else
			return 0;
	}
	mutex_lock(&sysfs_mutex);
	off = filp->f_pos;
	for (pos = sysfs_dir_pos(ns, parent_sd, filp->f_pos, pos);
	     pos;
	     pos = sysfs_dir_next_pos(ns, parent_sd, filp->f_pos, pos)) {
		const char * name;
		unsigned int type;
		int len, ret;

		name = pos->s_name;
		len = strlen(name);
		ino = pos->s_ino;
		type = dt_type(pos);
		off = filp->f_pos = pos->s_hash;
		filp->private_data = sysfs_get(pos);

		mutex_unlock(&sysfs_mutex);
		ret = filldir(dirent, name, len, off, ino, type);
		mutex_lock(&sysfs_mutex);
		if (ret < 0)
			break;
	}
	mutex_unlock(&sysfs_mutex);

	/* don't reference last entry if its refcount is dropped */
	if (!pos) {
		filp->private_data = NULL;

		/* EOF and not changed as 0 or 1 in read/write path */
		if (off == filp->f_pos && off > 1)
			filp->f_pos = INT_MAX;
	}
	return 0;
}

static loff_t sysfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t ret;

	mutex_lock(&inode->i_mutex);
	ret = generic_file_llseek(file, offset, whence);
	mutex_unlock(&inode->i_mutex);

	return ret;
}

const struct file_operations sysfs_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= sysfs_readdir,
	.release	= sysfs_dir_release,
	.llseek		= sysfs_dir_llseek,
};
