// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

#ifndef _SECP256K1_DCRM_EXT_
# define _SECP256K1_DCRM_EXT_

int secp256k1_get_ecdsa_sign_v(const secp256k1_context* ctx, unsigned char *point,const unsigned char *scalar)
{
	int ret = 0;
	int overflow = 0;
	secp256k1_fe feY;
	secp256k1_scalar s;

	secp256k1_fe_set_b32(&feY, point);
	secp256k1_scalar_set_b32(&s, scalar, &overflow);
	
	ret = (overflow ? 2 : 0) | (secp256k1_fe_is_odd(&feY) ? 1 : 0);
	return ret;
}

#endif
