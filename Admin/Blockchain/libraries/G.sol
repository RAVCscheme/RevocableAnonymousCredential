// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {BN256G2} from "./BN256G2.sol";

library G {

   	// p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 internal constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 internal constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 internal constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 internal constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

	struct G1Point {
		uint256 X;
		uint256 Y;
	}

	// Encoding of field elements is: X[0] * z + X[1]
	struct G2Point {
		uint256[2] X;
		uint256[2] Y;
	}

	// (P+1) / 4
	function A() pure internal returns (uint256) {
		return CURVE_A;
	}

	function P() pure internal returns (uint256) {
		return FIELD_ORDER;
	}

	function N() pure internal returns (uint256) {
		return GEN_ORDER;
	}

	/// @return the generator of G1
	function P1() pure internal returns (G1Point memory) {
		return G1Point(1, 2);
	}

	function _modInv(uint256 a, uint256 n) internal view returns (uint256 result) {
        bool success;
        assembly {
            let freemem := mload(0x40)
            mstore(freemem, 0x20)
            mstore(add(freemem,0x20), 0x20)
            mstore(add(freemem,0x40), 0x20)
            mstore(add(freemem,0x60), a)
            mstore(add(freemem,0x80), sub(n, 2))
            mstore(add(freemem,0xA0), n)
            success := staticcall(sub(gas(), 2000), 5, freemem, 0xC0, freemem, 0x20)
            result := mload(freemem)
        }
        require(success);
    }

	function do_ecdsa_verify(G1Point memory commit, G1Point memory pk, uint256[2] memory sign) view internal returns(bool){
	    bytes32 hash_digest = G1_to_binary256(commit);
	    uint256 s1 = _modInv(sign[1], N());
	    uint256 x1 = mulmod(uint256(hash_digest), s1, N());
	    uint256 x2 = mulmod(sign[0], s1, N());
	    G1Point memory tmp = g1mul(P1(), x1);
	    tmp = g1add(tmp, g1mul(pk, x2));
	    return tmp.X == sign[0];
  }

  function HashToPoint(uint256 s)
        internal view returns (G1Point memory)
    {
        uint256 beta = 0;
        uint256 y = 0;

        // XXX: Gen Order (n) or Field Order (p) ?
        uint256 x = s % GEN_ORDER;

        while( true ) {
            (beta, y) = FindYforX(x);

            // y^2 == beta
            if( beta == mulmod(y, y, FIELD_ORDER) ) {
                return G1Point(x, y);
            }

            x = addmod(x, 1, FIELD_ORDER);
        }
    }

    /**
    * Given X, find Y
    *
    *   where y = sqrt(x^3 + b)
    *
    * Returns: (x^3 + b), y
    */
    function FindYforX(uint256 x)
        internal view returns (uint256, uint256)
    {
        // beta = (x^3 + b) % p
        uint256 beta = addmod(mulmod(mulmod(x, x, FIELD_ORDER), x, FIELD_ORDER), CURVE_B, FIELD_ORDER);

        // y^2 = x^3 + b
        // this acts like: y = sqrt(beta)
        uint256 y = expMod(beta, CURVE_A, FIELD_ORDER);

        return (beta, y);
    }


    // a - b = c;
    function submod(uint a, uint b) internal pure returns (uint){
        uint a_nn;
        if(a>b) {
            a_nn = a;
        } else {
            a_nn = a+GEN_ORDER;
        }
        return addmod(a_nn - b, 0, GEN_ORDER);
    }


    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
        internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly{
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return output[0];
    }


	/// @return the generator of G2
	function P2() pure internal returns (G2Point memory) {
		return G2Point(
			[11559732032986387107991004021392285783925812861821192530917403151452391805634,
			 10857046999023057135944570762232829481370756359578518086990519993285655852781],
			[4082367875863433681332203403145435568316851327593401208105741076214120093531,
			 8495653923123431417604973247489272438418190587263600148770280649306958101930]
		);
	}

	/// @return the negation of p, i.e. p.add(p.negate()) should be zero.
	function g1neg(G1Point memory p) pure internal returns (G1Point memory) {
		// The prime q in the base field F_q for G1
		uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
		if (p.X == 0 && p.Y == 0)
			return G1Point(0, 0);
		return G1Point(p.X, q - (p.Y % q));
	}

	function isinf(G1Point memory p) pure internal returns (bool) {
		if (p.X == 0 && p.Y == 0) {
			return true;
		}
		return false;
	}

	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
			// Use "invalid" to make gas estimation work
			switch success case 0 { invalid() }
		}
		require(success);
	}

	function g2add(G2Point memory p1, G2Point memory p2) view internal returns (G2Point memory r) {
		(r.X[1], r.X[0], r.Y[1], r.Y[0]) = BN256G2.ECTwistAdd(p1.X[1], p1.X[0], p1.Y[1], p1.Y[0], p2.X[1], p2.X[0], p2.Y[1], p2.Y[0]);
		return r;
	}

	function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
			// Use "invalid" to make gas estimation work
			switch success case 0 { invalid() }
		}
		require (success);
	}


	/// @return the result of computing the pairing check
	/// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
	/// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
	/// return true.
	function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
		require(p1.length == p2.length);
		uint elements = p1.length;
		uint inputSize = elements * 6;
		uint[] memory input = new uint[](inputSize);
		for (uint i = 0; i < elements; i++)
		{
			input[i * 6 + 0] = p1[i].X;
			input[i * 6 + 1] = p1[i].Y;
			input[i * 6 + 2] = p2[i].X[0];
			input[i * 6 + 3] = p2[i].X[1];
			input[i * 6 + 4] = p2[i].Y[0];
			input[i * 6 + 5] = p2[i].Y[1];
		}
		uint[1] memory out;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
			// Use "invalid" to make gas estimation work
			switch success case 0 { invalid() }
		}
		require(success);
		return out[0] != 0;
	}
	
	function G1_to_binary256(G1Point memory point) internal pure returns (bytes32) {
      bytes32 X = bytes32(point.X);
      bytes32 Y = bytes32(point.Y);
      bytes memory result = new bytes(64);
      uint i = 0;
      for (i=0; i< 32 ; i++) {
          result[i] = X[i];
      }
      for (i=0; i< 32 ; i++) {
          result[32 + i] = Y[i];
      }
     return sha256(result);
  }

  function G2_to_binary256(G2Point memory point) internal pure returns (bytes32) {
      
      bytes memory result = new bytes(128);
      bytes32 X = bytes32(point.X[1]);
      uint i = 0;
      for (i=0; i< 32 ; i++) {
          result[i] = X[i];
      }
      X = bytes32(point.X[0]);
      for (i=0; i< 32 ; i++) {
          result[32 + i] = X[i];
      }
      X = bytes32(point.Y[1]);
      for (i=0; i< 32 ; i++) {
          result[64 + i] = X[i];
      }
      X = bytes32(point.Y[0]);
      for (i=0; i< 32 ; i++) {
          result[96 + i] = X[i];
      }
      return sha256(result);
  }

  function EC_to_binary256(uint256 _X, uint256 _Y) internal pure returns(bytes32) {
      bytes32 X = bytes32(_X);
      bytes32 Y = bytes32(_Y);
      bytes memory result = new bytes(64);
      uint i = 0;
      for (i=0; i< 32 ; i++) {
          result[i] = X[i];
      }
      for (i=0; i< 32 ; i++) {
          result[32 + i] = Y[i];
      }
     return sha256(result);
  }
  
  function ec_sum(G2Point[] memory points) internal view returns(G2Point memory) {
  G2Point memory result = G2Point([uint256(0),0],[uint256(0),0]);
  uint i = 0;
  for(i=0; i<points.length; i++) 
  {
    result = g2add(result, points[i]);
  }
  return result;
}
}