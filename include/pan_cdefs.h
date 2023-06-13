// Copyright 2023 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// \file
/// PAN C Wrapper

#ifndef PAN_INCLUDE_GUARD
#define PAN_INCLUDE_GUARD

#include <stddef.h>
#include <stdint.h>

#define PAN_INVALID_HANDLE 0
#define PAN_ERR_OK 0
#define PAN_ERR_FAILED 1
#define PAN_ERR_DEADLINE 2
#define PAN_ERR_NO_PATH 3
#define PAN_ERR_ADDR_SYNTAX 4
#define PAN_ERR_ADDR_RESOLUTION 5

typedef const void cvoid_t;
typedef const char cchar_t;
typedef const uint8_t cuint8_t;
typedef const uint64_t cuint64_t;
typedef uint32_t PanError;
typedef uintptr_t PanUDPAddr;
typedef uintptr_t PanConn;
typedef uintptr_t PanListenConn;
typedef uintptr_t PanPath;
typedef uintptr_t PanPathFingerprint;
typedef uintptr_t PanPathInterface;
typedef uintptr_t PanPolicy;
typedef uintptr_t PanSelector;
typedef uintptr_t PanReplySelector;
typedef uintptr_t PanConnSockAdapter;
typedef uintptr_t PanListenSockAdapter;

////////////
// Policy //
////////////

typedef PanPath (*PanPolicyFilterFn)(PanPath* paths, size_t count, uintptr_t user);

/// \brief The filter callback can permute and truncate the given path array.
/// The new size must be returned from the callback.
/// \warning The path handles are only valid during the callback and must not be
// stored by the callee.
inline size_t panCallPolicyFilter(PanPolicyFilterFn f, PanPath* paths, size_t count, uintptr_t user)
{
	return f(paths, count, user);
}

//////////////
// Selector //
//////////////

typedef PanPath (*PanSelectorPathFn)(uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanSelectorInitializeFn)(
	PanUDPAddr local, PanUDPAddr remote, PanPath* paths, size_t count, uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanSelectorRefreshFn)(PanPath* paths, size_t count, uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanSelectorPathDownFn)(PanPathFingerprint pf, PanPathInterface pi, uintptr_t user);

typedef void (*PanSelectorClose)(uintptr_t user);

struct PanSelectorCallbacks
{
	PanSelectorPathFn       path;
	PanSelectorInitializeFn initialize;
	PanSelectorRefreshFn    refresh;
	PanSelectorPathDownFn   pathDown;
	PanSelectorClose        close;
};

inline uintptr_t panCallSelectorPath(PanSelectorPathFn f, uintptr_t user)
{
	return f(user);
}

inline void panCallSelectorInitialize(PanSelectorInitializeFn f,
	PanUDPAddr local, PanUDPAddr remote, PanPath* paths, size_t count, uintptr_t user)
{
	f(local, remote, paths, count, user);
}

inline void panCallSelectorRefresh(PanSelectorRefreshFn f,
	PanPath* paths, size_t count, uintptr_t user)
{
	f(paths, count, user);
}

inline void panCallSelectorPathDown(PanSelectorPathDownFn f,
	PanPathFingerprint pf, PanPathInterface pi, uintptr_t user)
{
	f(pf, pi, user);
}

inline void panCallSelectorClose(PanSelectorClose f, uintptr_t user)
{
	f(user);
}

///////////////////
// ReplySelector //
///////////////////

/// Handles must be deleted by callee.
typedef PanPath (*PanReplySelPathFn)(PanUDPAddr remote, uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanReplySelInitializeFn)(PanUDPAddr local, uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanReplySelRecordFn)(PanUDPAddr remote, PanPath path, uintptr_t user);

/// Handles must be deleted by callee.
typedef void (*PanReplySelPathDownFn)(PanPathFingerprint pf, PanPathInterface pi, uintptr_t user);

typedef void (*PanReplySelCloseFn)(uintptr_t user);

struct PanReplySelCallbacks
{
	PanReplySelPathFn       path;
	PanReplySelInitializeFn initialize;
	PanReplySelRecordFn     record;
	PanReplySelPathDownFn   pathDown;
	PanReplySelCloseFn      close;
};

inline uintptr_t panCallReplySelPath(PanReplySelPathFn f, PanUDPAddr remote, uintptr_t user)
{
	return f(remote, user);
}

inline void panCallReplySelInitialize(PanReplySelInitializeFn f, PanUDPAddr local, uintptr_t user)
{
	f(local, user);
}

inline void panCallReplySelRecord(PanReplySelRecordFn f,
	PanUDPAddr remote, PanPath path, uintptr_t user)
{
	f(remote, path, user);
}

inline void panCallReplySelPathDown(PanReplySelPathDownFn f,
	PanPathFingerprint pf, PanPathInterface pi, uintptr_t user)
{
	f(pf, pi, user);
}

inline void panCallReplySelClose(PanReplySelCloseFn f, uintptr_t user)
{
	f(user);
}

#endif // PAN_INCLUDE_GUARD
