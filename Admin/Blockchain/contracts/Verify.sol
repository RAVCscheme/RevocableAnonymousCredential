// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import { G } from "../libraries/G.sol";
import {Params} from "./Params.sol";

contract Verify {

  Params private params;
  address private owner;

    constructor(Params _params) {
        owner = msg.sender;
        params = _params;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
 
  function set_params(address addr) public onlyOwner {
    params = Params(addr);
  }

  mapping(uint256 => mapping(uint256 => uint256[])) private policy;
  mapping(uint256 => uint256) private policy_ids;
  
  function getPolicy(string memory name, uint256 policy_id) public view returns (uint256[] memory) {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        require(policy_id > 0 && policy_id <= policy_ids[id], "No such policy id");
        return policy[id][policy_id];
    }

  function setPolicy(string memory name, uint256[][] memory _policy) public onlyOwner {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        for (uint256 i= 0; i <_policy.length; i++) {
          policy[id][1+policy_ids[id]] = _policy[i];
          policy_ids[id] = policy_ids[id] + 1; // total count of policy ids will be here for a title. then u can use what policy's are needed from getPolicy for that title.
        }
  }

  function gettotalPolicies(string memory name) public view returns (uint256) {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        return policy_ids[id];
  }

    struct Theta {
        G.G2Point kappa;
        G.G1Point nu;
        G.G1Point[2] sigma;
        Proof proof;
    }
   
    struct Proof {
        uint256 c;
        uint256[] rm;
        uint256 rt;
    }

  event emitVerify(uint256 indexed id, uint256[4] credential, string[] public_m, uint256[] disclosed_indexes, string[] disclosed_attributes);

  function stringToUint256(string memory s) private pure returns (uint256 result) {
    bytes memory b = bytes(s);
    result = 0;
    for (uint16 i = 0; i < b.length; i++) {
      uint c = uint8(b[i]);
      if (c >= 48 && c <= 57) {
        result = result * 10 + (c - 48);
      }
    }
  }
    

  function VerifyCred(string memory name, Theta memory theta, string[] memory public_m, G.G2Point memory Aw, G.G2Point memory aggr, uint256[] memory disclose_index, string[] memory disclose_attr, uint256[] memory disclose_attr_enc, uint256 _timestamp) public {
    
    require(block.timestamp >= _timestamp - 300 && block.timestamp < _timestamp + 600);
    G.G2Point[] memory beta = params.get_beta(name);
    require(public_m.length + theta.proof.rm.length + disclose_attr.length <= beta.length);
    
    require(verify_pi_v(name, [theta.sigma[0], theta.nu], [Aw, theta.kappa], theta.proof, beta, disclose_attr, disclose_attr_enc, disclose_index, _timestamp));
    uint256[] memory public_m_enc = params.get_public_m_encoding(name);
    if(public_m.length != 0) {
      require(check_aggr(public_m, public_m_enc, aggr, beta, theta.proof.rm.length+disclose_attr.length));
    }
    
    G.G1Point[] memory coord1 = new G.G1Point[](2);
    G.G2Point[] memory coord2 = new G.G2Point[](2);
    coord1[0] = G.g1neg(theta.sigma[0]);
    coord1[1] = G.g1add(theta.sigma[1], theta.nu);
    coord2[0] = G.g2add(theta.kappa, aggr);
    coord2[1] = G.P2();
    require(!G.isinf(theta.sigma[0]) && G.pairing(coord1, coord2));
    logging(name, theta.sigma, public_m, disclose_index, disclose_attr);
  }

  function logging(string memory name, G.G1Point[2] memory sigma, string[] memory public_m, uint256[] memory disclose_index, string[] memory disclose_attr) private {
    uint256 id = params.getMapCredentials(name);
    require(id != 0, "No such AC.");
    uint256[4] memory credential = [sigma[0].X, sigma[0].Y, sigma[1].X, sigma[1].Y];
    emit emitVerify(id, credential, public_m, disclose_index, disclose_attr);
  }
 
  function check_aggr(string[] memory public_m, uint256[] memory public_m_enc, G.G2Point memory aggr, G.G2Point[] memory beta, uint256 priv_attr_len) view internal returns (bool) {
    G.G1Point[] memory AA = new G.G1Point[](public_m.length+1);
    G.G2Point[] memory AB = new G.G2Point[](public_m.length+1);
    AA[0] = G.g1neg(G.P1());
    AB[0] = aggr;
    uint256[] memory uint_public_m = new uint256[](public_m.length);
    for(uint256 i = 0; i < public_m.length; i++) {
      if (public_m_enc[i] == 1) {
        uint_public_m[i] = uint256(sha256(bytes(public_m[i])))%G.N();
      }
      else{
        uint_public_m[i] = stringToUint256(public_m[i]);
      }
    }
    for(uint256 i = 0; i < public_m.length; i++) {
      AA[i+1] = G.g1mul(G.P1(), uint_public_m[i]);
      AB[i+1] = beta[priv_attr_len + i];
    }
    if (!G.pairing(AA, AB)) {
      return false;
    }
    return true;
  }

  function calculate_Bw(G.G1Point[2] memory h_nu, Proof memory proof) private view returns(G.G1Point memory) {
    return (G.g1add(G.g1mul(h_nu[1], proof.c), G.g1mul(h_nu[0], proof.rt)));
  }

  function verify_pi_v(string memory name, G.G1Point[2] memory h_nu, G.G2Point[2] memory Aw_kappa, Proof memory proof, G.G2Point[] memory beta, string[] memory disclose_attr, uint256[] memory disclose_attr_enc, uint256[] memory disclose_index, uint256 _timestamp) internal view returns (bool) {
    G.G2Point memory alpha = params.get_alpha(name);

    uint256[] memory uint_disclose_attr = new uint256[](disclose_attr.length);
    for(uint256 i = 0; i< disclose_attr.length; i++) {
      if (disclose_attr_enc[i] == 1) {
        uint_disclose_attr[i] = uint256(sha256(bytes(disclose_attr[i])))%G.N();
      }
      else{
        uint_disclose_attr[i] = stringToUint256(disclose_attr[i]);
      }
    }

    if(!check_Aw(Aw_kappa, proof, alpha, beta, uint_disclose_attr, disclose_index)) {
      return false;
    }

    G.G1Point memory Bw = calculate_Bw(h_nu, proof);
    G.G1Point[] memory hs = params.get_hs(name);
    return proof.c == ToChallenge(alpha, Aw_kappa, Bw, hs, beta, uint_disclose_attr, _timestamp);
  }
  
  function check_Aw(G.G2Point[2] memory Aw_kappa, Proof memory proof, G.G2Point memory alpha, G.G2Point[] memory beta, uint256[] memory disclose_attr, uint256[] memory disclose_index) private view returns(bool) {
    G.G1Point[] memory AA = new G.G1Point[](proof.rm.length+disclose_attr.length+5);
    G.G2Point[] memory AB = new G.G2Point[](proof.rm.length+disclose_attr.length+5);
    AA[0] = G.g1neg(G.P1());
    AA[1] = G.P1();
    AA[2] = G.g1neg(G.g1mul(G.P1(), proof.c));
    AA[3] = G.g1mul(G.P1(), proof.rt);
    AA[4] = G.g1mul(G.P1(), proof.c);
    AB[0] = Aw_kappa[0];
    AB[1] = alpha;
    AB[2] = alpha;
    AB[3] = G.P2();
    AB[4] = Aw_kappa[1];

    uint256 k = 0;
    uint256 j = 0;
    for(uint256 i=0; i< proof.rm.length + disclose_attr.length; i++) {
      if(disclose_index[i] == 1) {
        AA[i+5] = G.g1neg(G.g1mul(G.P1(), mulmod(proof.c, disclose_attr[k], G.N())));
        AB[i+5] = beta[i];
        k = k +1;
      }
      else {
        AA[i+5] = G.g1mul(G.P1(), proof.rm[j]);
        AB[i+5] = beta[i];
        j = j + 1;
      }   
    }
    if (!G.pairing(AA, AB)) {
      return false;
    }
    return true;
  }

  function ToChallenge(G.G2Point memory alpha, G.G2Point[2] memory Aw_kappa, G.G1Point memory Bw, G.G1Point[] memory _hs, G.G2Point[] memory beta, uint256[] memory disclose_attr, uint256 _timestamp) private pure returns (uint256) {
    bytes memory result = new bytes(224 + (_hs.length + beta.length + disclose_attr.length) * 32);
  
    bytes32 X =  G.G1_to_binary256(G.P1());
    for (uint256 i=0; i < 32 ; i++) {
      result[i] = X[i];
    }
    X =  G.G2_to_binary256(G.P2());
    for (uint256 i=0; i< 32 ; i++) {
      result[i+32] = X[i];
    }
    X =  G.G2_to_binary256(alpha);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+64] = X[i];
    }
    X =  G.G2_to_binary256(Aw_kappa[0]);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+96] = X[i];
    }
    X =  G.G1_to_binary256(Bw);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+128] = X[i];
    }
    X =  G.G2_to_binary256(Aw_kappa[1]);
    for (uint256 i=0; i< 32 ; i++) {
      result[i+160] = X[i];
    }
  
    uint256 location = 192;
    for(uint256 i=0; i< _hs.length; i++) {
      X = G.G1_to_binary256(_hs[i]);
      for (uint256 j=0; j< 32 ; j++) {
        result[j+location] = X[j];
      }
      location = location + 32;
    }
    for(uint256 i = 0; i < beta.length; i++) {
      X = G.G2_to_binary256(beta[i]);
      for (uint256 j=0; j< 32 ; j++) {
        result[j+location] = X[j];
      }
      location = location + 32;
    }
    for(uint256 i = 0; i < disclose_attr.length; i++) {
      X = bytes32(disclose_attr[i]);
      for (uint256 j=0; j< 32 ; j++) {
        result[j+location] = X[j];
      }
      location = location + 32;
    }
    X = bytes32(_timestamp);
    for(uint256 i = 0; i < 32; i++) {
      result[i+location] = X[i];
    }
    location = location + 32;

    bytes32 Chash =  sha256(result);
    return uint256(Chash);
  }
}
