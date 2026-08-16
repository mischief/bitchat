// SPDX-License-Identifier: ISC
#ifndef BITCHAT_EXPORT_H
#define BITCHAT_EXPORT_H

#ifdef BITCHAT_BUILDING
#define BC_API __attribute__((visibility("default")))
#else
#define BC_API
#endif

#endif
