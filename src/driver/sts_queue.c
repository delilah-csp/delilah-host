#include <linux/mutex.h>
#include <linux/slab.h>

#include "sts_queue.h"

typedef struct StsElement {
  void *next;
  void *value;
} StsElement;

static DEFINE_MUTEX(mutex);

struct StsHeader {
  StsElement *head;
  StsElement *tail;
};

static StsHeader* create(void) {
  StsHeader *handle = kmalloc(sizeof(*handle), GFP_KERNEL);
  handle->head = NULL;
  handle->tail = NULL;

  return handle;
}

static void destroy(StsHeader *header) {
  kfree(header);
  header = NULL;
}

static void push(StsHeader *header, void *elem) {
  StsElement* oldTail;
  StsElement *element = kmalloc(sizeof(*element), GFP_KERNEL);
  element->value = elem;
  element->next = NULL;

  mutex_lock(&mutex);
  // Is list empty
  if (header->head == NULL) {
	header->head = element;
	header->tail = element;
  } else {
	// Rewire
	oldTail = header->tail;
	oldTail->next = element;
	header->tail = element;
  }
  mutex_unlock(&mutex);
}

static void* pop(StsHeader *header) {
  void *value;
  StsElement *head = header->head;
  mutex_lock(&mutex);

  // Is empty?
  if (head == NULL) {
	mutex_unlock(&mutex);
	return NULL;
  } else {
	// Rewire
	header->head = head->next;
	
	// Get head and free element memory
	value = head->value;
	kfree(head);
	
	mutex_unlock(&mutex);
	return value;
  }
}

_StsQueue const StsQueue = {
  create,
  destroy,
  push,
  pop
};
