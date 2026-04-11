/*
 * Shared C preamble for cgo bindings against CryptoPro CSP (CAPILite) and
 * CryptoPro CAdES on Linux.
 *
 * Headers live in /opt/cprocsp/include/{cpcsp,cades} and require these
 * platform macros to be defined before inclusion (per CryptoPro SDK docs).
 *
 * Libraries (linked via LDFLAGS in every .go file that uses cgo in this
 * package): libcapi10, libcapi20, libssp, libcades, librdrsup.
 *
 * NOTE: This file is not compiled on its own — it is included verbatim from
 * every .go file in the package via an `#include "capi.h"` in the cgo preamble.
 * The #cgo directives are duplicated in each .go file because cgo does not
 * honour them from headers.
 */
#ifndef GOST_CRYPTO_INTERNAL_CRYPTOPRO_CAPI_H
#define GOST_CRYPTO_INTERNAL_CRYPTOPRO_CAPI_H

#define UNIX
#define HAVE_LIMITS_H
#ifndef SIZEOF_VOID_P
#define SIZEOF_VOID_P 8
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
#include <WinCryptEx.h>
#include <CAdES.h>

/*
 * CryptoPro CSP exposes GOST ALG_IDs that are not always present in every
 * header revision. The values below are from the CryptoPro SDK reference
 * and are used when the headers omit them. They must match the live CSP.
 */
#ifndef CALG_GR3411_2012_256
#define CALG_GR3411_2012_256 0x00008021
#endif
#ifndef CALG_GR3411_2012_512
#define CALG_GR3411_2012_512 0x00008022
#endif
#ifndef CALG_GR3410_2012_256
#define CALG_GR3410_2012_256 0x00002e49
#endif
#ifndef CALG_GR3410_2012_512
#define CALG_GR3410_2012_512 0x00002e3d
#endif
#ifndef CALG_PRO_HMAC_2012_256
#define CALG_PRO_HMAC_2012_256 0x0000802f
#endif
#ifndef CALG_PRO_HMAC_2012_512
#define CALG_PRO_HMAC_2012_512 0x00008030
#endif
#ifndef CALG_G28147
#define CALG_G28147 0x0000661e
#endif
#ifndef CALG_GR3412_2015_M
#define CALG_GR3412_2015_M 0x00006643
#endif
#ifndef CALG_GR3412_2015_K
#define CALG_GR3412_2015_K 0x00006640
#endif
#ifndef CALG_G28147_IMIT
#define CALG_G28147_IMIT 0x0000801f
#endif
#ifndef CALG_GR3412_2015_M_IMIT
#define CALG_GR3412_2015_M_IMIT 0x00008025
#endif
#ifndef CALG_GR3412_2015_K_IMIT
#define CALG_GR3412_2015_K_IMIT 0x00008024
#endif

#ifndef PROV_GOST_2012_256
#define PROV_GOST_2012_256 80
#endif
#ifndef PROV_GOST_2012_512
#define PROV_GOST_2012_512 81
#endif

#ifndef KP_DHOID
#define KP_DHOID 36
#endif
#ifndef KP_HASHOID
#define KP_HASHOID 21
#endif
#ifndef KP_CIPHEROID
#define KP_CIPHEROID 19
#endif
#ifndef KP_SV
#define KP_SV 0x00000025
#endif

#endif /* GOST_CRYPTO_INTERNAL_CRYPTOPRO_CAPI_H */
