/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#if !defined (__VG_AVL_H__)
#define __VG_AVL_H__

#include <assert.h>

/*
 * AVL tree implementation
 */

typedef enum { CENT = 1, LEFT = 0, RIGHT = 2 } avl_balance_t;

typedef struct _avl_item_s {
	struct _avl_item_s *ai_left, *ai_right, *ai_up;
	avl_balance_t ai_balance;
#ifndef NDEBUG
	int ai_indexed;
#endif
} avl_item_t;

typedef struct _avl_root_s {
	avl_item_t *ar_root;
} avl_root_t;

static INLINE void
avl_root_init(avl_root_t *rootp)
{
	rootp->ar_root = NULL;
}

static INLINE int
avl_root_empty(avl_root_t *rootp)
{
	return (rootp->ar_root == NULL) ? 1 : 0;
}

static INLINE void
avl_item_init(avl_item_t *itemp)
{
	itemp->ai_left = NULL;
	itemp->ai_right = NULL;
	itemp->ai_up = NULL;
	itemp->ai_balance = CENT;
#ifndef NDEBUG
	itemp->ai_indexed = 0;
#endif
}

#define container_of(ptr, type, member) \
	(((type*) (((unsigned char *)ptr) - \
		   (size_t)&(((type *)((unsigned char *)0))->member))))

#define avl_item_entry(ptr, type, member) \
	container_of(ptr, type, member)



static INLINE void
_avl_rotate_ll(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *tmp;
	tmp = itemp->ai_left;
	itemp->ai_left = tmp->ai_right;
	if (itemp->ai_left)
		itemp->ai_left->ai_up = itemp;
	tmp->ai_right = itemp;

	if (itemp->ai_up) {
		if (itemp->ai_up->ai_left == itemp) {
			itemp->ai_up->ai_left = tmp;
		} else {
			assert(itemp->ai_up->ai_right == itemp);
			itemp->ai_up->ai_right = tmp;
		}
	} else {
		rootp->ar_root = tmp;
	}
	tmp->ai_up = itemp->ai_up;
	itemp->ai_up = tmp;
}

static INLINE void
_avl_rotate_lr(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *rcp, *rlcp;
	rcp = itemp->ai_left;
	rlcp = rcp->ai_right;
	if (itemp->ai_up) {
		if (itemp == itemp->ai_up->ai_left) {
			itemp->ai_up->ai_left = rlcp;
		} else {
			assert(itemp == itemp->ai_up->ai_right);
			itemp->ai_up->ai_right = rlcp;
		}
	} else {
		rootp->ar_root = rlcp;
	}
	rlcp->ai_up = itemp->ai_up;
	rcp->ai_right = rlcp->ai_left;
	if (rcp->ai_right)
		rcp->ai_right->ai_up = rcp;
	itemp->ai_left = rlcp->ai_right;
	if (itemp->ai_left)
		itemp->ai_left->ai_up = itemp;
	rlcp->ai_left = rcp;
	rlcp->ai_right = itemp;
	rcp->ai_up = rlcp;
	itemp->ai_up = rlcp;
}

static INLINE void
_avl_rotate_rr(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *tmp;
	tmp = itemp->ai_right;
	itemp->ai_right = tmp->ai_left;
	if (itemp->ai_right)
		itemp->ai_right->ai_up = itemp;
	tmp->ai_left = itemp;

	if (itemp->ai_up) {
		if (itemp->ai_up->ai_right == itemp) {
			itemp->ai_up->ai_right = tmp;
		} else {
			assert(itemp->ai_up->ai_left == itemp);
			itemp->ai_up->ai_left = tmp;
		}
	} else {
		rootp->ar_root = tmp;
	}
	tmp->ai_up = itemp->ai_up;
	itemp->ai_up = tmp;
}

static INLINE void
_avl_rotate_rl(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *rcp, *rlcp;
	rcp = itemp->ai_right;
	rlcp = rcp->ai_left;
	if (itemp->ai_up) {
		if (itemp == itemp->ai_up->ai_right) {
			itemp->ai_up->ai_right = rlcp;
		} else {
			assert(itemp == itemp->ai_up->ai_left);
			itemp->ai_up->ai_left = rlcp;
		}
	} else {
		rootp->ar_root = rlcp;
	}
	rlcp->ai_up = itemp->ai_up;
	rcp->ai_left = rlcp->ai_right;
	if (rcp->ai_left)
		rcp->ai_left->ai_up = rcp;
	itemp->ai_right = rlcp->ai_left;
	if (itemp->ai_right)
		itemp->ai_right->ai_up = itemp;
	rlcp->ai_right = rcp;
	rlcp->ai_left = itemp;
	rcp->ai_up = rlcp;
	itemp->ai_up = rlcp;
}

static void
avl_delete_fix(avl_root_t *rootp, avl_item_t *itemp, avl_item_t *parentp)
{
	avl_item_t *childp;

	if ((parentp->ai_left == NULL) &&
	    (parentp->ai_right == NULL)) {
		assert(itemp == NULL);
		parentp->ai_balance = CENT;
		itemp = parentp;
		parentp = itemp->ai_up;
	}

	while (parentp) {
		if (itemp == parentp->ai_right) {
			itemp = parentp->ai_left;
			if (parentp->ai_balance == LEFT) {
				/* Parent was left-heavy, now worse */
				if (itemp->ai_balance == LEFT) {
					/* If left child is also
					 * left-heavy, LL fixes it. */
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					parentp = itemp;
				} else if (itemp->ai_balance == CENT) {
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = RIGHT;
					parentp->ai_balance = LEFT;
					break;
				} else {
					childp = itemp->ai_right;
					_avl_rotate_lr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						itemp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						parentp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					parentp = childp;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = LEFT;
				break;
			} else {
				parentp->ai_balance = CENT;
			}

		} else {
			itemp = parentp->ai_right;
			if (parentp->ai_balance == RIGHT) {
				if (itemp->ai_balance == RIGHT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					parentp = itemp;
				} else if (itemp->ai_balance == CENT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = LEFT;
					parentp->ai_balance = RIGHT;
					break;
				} else {
					childp = itemp->ai_left;
					_avl_rotate_rl(rootp, parentp);

					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						parentp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						itemp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					parentp = childp;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = RIGHT;
				break;
			} else {
				parentp->ai_balance = CENT;
			}
		}

		itemp = parentp;
		parentp = itemp->ai_up;
	}
}

static void
avl_insert_fix(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *childp, *parentp = itemp->ai_up;
	itemp->ai_left = itemp->ai_right = NULL;
#ifndef NDEBUG
	assert(!itemp->ai_indexed);
	itemp->ai_indexed = 1;
#endif
	while (parentp) {
		if (itemp == parentp->ai_left) {
			if (parentp->ai_balance == LEFT) {
				/* Parent was left-heavy, now worse */
				if (itemp->ai_balance == LEFT) {
					/* If left child is also
					 * left-heavy, LL fixes it. */
					_avl_rotate_ll(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					break;
				} else {
					assert(itemp->ai_balance != CENT);
					childp = itemp->ai_right;
					_avl_rotate_lr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						itemp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						parentp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					break;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = LEFT;
			} else {
				parentp->ai_balance = CENT;
				return;
			}
		} else {
			if (parentp->ai_balance == RIGHT) {
				if (itemp->ai_balance == RIGHT) {
					_avl_rotate_rr(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					break;
				} else {
					assert(itemp->ai_balance != CENT);
					childp = itemp->ai_left;
					_avl_rotate_rl(rootp, parentp);
					itemp->ai_balance = CENT;
					parentp->ai_balance = CENT;
					if (childp->ai_balance == RIGHT)
						parentp->ai_balance = LEFT;
					if (childp->ai_balance == LEFT)
						itemp->ai_balance = RIGHT;
					childp->ai_balance = CENT;
					break;
				}
			} else if (parentp->ai_balance == CENT) {
				parentp->ai_balance = RIGHT;
			} else {
				parentp->ai_balance = CENT;
				break;
			}
		}

		itemp = parentp;
		parentp = itemp->ai_up;
	}
}

static INLINE avl_item_t *
avl_first(avl_root_t *rootp)
{
	avl_item_t *itemp = rootp->ar_root;
	if (itemp) {
		while (itemp->ai_left)
			itemp = itemp->ai_left;
	}
	return itemp;
}

static INLINE avl_item_t *
avl_next(avl_item_t *itemp)
{
	if (itemp->ai_right) {
		itemp = itemp->ai_right;
		while (itemp->ai_left)
			itemp = itemp->ai_left;
		return itemp;
	}

	while (itemp->ai_up && (itemp == itemp->ai_up->ai_right))
		itemp = itemp->ai_up;

	if (!itemp->ai_up)
		return NULL;

	return itemp->ai_up;
}

static void
avl_remove(avl_root_t *rootp, avl_item_t *itemp)
{
	avl_item_t *relocp, *replacep, *parentp = NULL;
#ifndef NDEBUG
	assert(itemp->ai_indexed);
	itemp->ai_indexed = 0;
#endif
	/* If the item is directly replaceable, do it. */
	if ((itemp->ai_left == NULL) || (itemp->ai_right == NULL)) {
		parentp = itemp->ai_up;
		replacep = itemp->ai_left;
		if (replacep == NULL)
			replacep = itemp->ai_right;
		if (replacep != NULL)
			replacep->ai_up = parentp;
		if (parentp == NULL) {
			rootp->ar_root = replacep;
		} else {
			if (itemp == parentp->ai_left)
				parentp->ai_left = replacep;
			else
				parentp->ai_right = replacep;

			avl_delete_fix(rootp, replacep, parentp);
		}
		return;
	}

	/*
	 * Otherwise we do an indirect replacement with
	 * the item's leftmost right descendant.
	 */
	relocp = avl_next(itemp);
	assert(relocp);
	assert(relocp->ai_up != NULL);
	assert(relocp->ai_left == NULL);
	replacep = relocp->ai_right;
	relocp->ai_left = itemp->ai_left;
	if (relocp->ai_left != NULL)
		relocp->ai_left->ai_up = relocp;
	if (itemp->ai_up == NULL)
		rootp->ar_root = relocp;
	else {
		if (itemp == itemp->ai_up->ai_left)
			itemp->ai_up->ai_left = relocp;
		else
			itemp->ai_up->ai_right = relocp;
	}
	if (relocp == relocp->ai_up->ai_left) {
		assert(relocp->ai_up != itemp);
		relocp->ai_up->ai_left = replacep;
		parentp = relocp->ai_up;
		if (replacep != NULL)
			replacep->ai_up = relocp->ai_up;
		relocp->ai_right = itemp->ai_right;
	} else {
		assert(relocp->ai_up == itemp);
		relocp->ai_right = replacep;
		parentp = relocp;
	}
	if (relocp->ai_right != NULL)
		relocp->ai_right->ai_up = relocp;
	relocp->ai_up = itemp->ai_up;
	relocp->ai_balance = itemp->ai_balance;
	avl_delete_fix(rootp, replacep, parentp);
}

#endif /* !defined (__VG_AVL_H__) */
