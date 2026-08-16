/* SPDX-License-Identifier: ISC */
#ifndef BITCHAT_BANNED_H
#define BITCHAT_BANNED_H

/*
 * Include this file last, after all system headers. #pragma GCC poison fires
 * on any token use including declarations inside system headers -- including
 * banned.h before them would poison the headers themselves.
 */

/* Dangerous string and input functions */
#pragma GCC poison gets strcpy strcat strncpy strncat strtok sprintf vsprintf

/* Unsafe integer parsers: no error detection */
#pragma GCC poison atoi atol atoll

/* Stack smashing hazards */
#ifdef alloca
#undef alloca
#endif
#pragma GCC poison alloca

#endif /* BITCHAT_BANNED_H */
