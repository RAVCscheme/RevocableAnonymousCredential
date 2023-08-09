// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {G} from "../libraries/G.sol";

contract Params {
    
    address private owner;  
    constructor() {    
        owner = msg.sender;
    }

    uint256 private credentialCount = 0;

    mapping(string => uint256) private mapCredentials;
    function setMapCredentials(string memory name) private {
        credentialCount += 1;
        mapCredentials[name] = credentialCount;  
    }

    function getMapCredentials(string memory name) public view returns (uint256) {
        return mapCredentials[name];
    }

    mapping(uint256 => G.G2Point) private alpha;
    mapping(uint256 => G.G1Point[]) private g1_beta;
    mapping(uint256 => G.G2Point[]) private beta;
    mapping(uint256 => G.G1Point[]) private hs;
    mapping(uint256 => uint256[]) private public_m_encoding;
    mapping(uint256 => G.G2Point[]) private opk;
    mapping(uint256 => G.G1Point[]) private beaver_public_key;
    mapping(uint256 =>  mapping(string => uint256[])) private include_indexes;
   // mapping(uint256 => string[][]) private ttp_combinations;

    uint256 private TTPCount = 0;
    mapping(string => uint256) private mapTTPs;
    function setMapTTPs(string memory name) private {
        TTPCount += 1;
        mapTTPs[name] = TTPCount;  
    }

    function getMapTTPs(string memory name) public view returns (uint256) {
        return mapTTPs[name];
    }

    mapping(uint256 => G.G1Point[]) private ttp_hs;
    mapping(uint256 => G.G1Point) private ttp_pk;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function set_params(string memory _name, G.G1Point[] memory _hs, G.G2Point memory _alpha, G.G1Point[] memory _g1_beta, G.G2Point[] memory _beta, G.G2Point[] memory _opk,G.G1Point[] memory abc, string[] memory _dependent_ttps, uint256[][] memory _include_indexes, uint256[] memory _public_m_encoding) public onlyOwner {
        require (getMapCredentials(_name) == 0, "AC name already exists.");
        setMapCredentials(_name);
        uint256 id = getMapCredentials(_name);
        for(uint256 i=0; i < _hs.length; i++) {
            hs[id].push(_hs[i]);
        }
        public_m_encoding[id] = _public_m_encoding;
        alpha[id] = _alpha;
        for(uint256 i=0; i < _beta.length; i++) {
            beta[id].push(_beta[i]);
        }
        for(uint256 i=0; i < _g1_beta.length; i++) {
            g1_beta[id].push(_g1_beta[i]);
        }
        for(uint256 i=0; i < _opk.length; i++) {
            opk[id].push(_opk[i]);
        }
        for(uint256 i=0; i < _include_indexes.length; i++) {
            include_indexes[id][_dependent_ttps[i]] = _include_indexes[i];
        }
        for(uint256 i=0; i < abc.length; i++) {
            beaver_public_key[id].push(abc[i]);
        }
        // for(uint256 i=0; i < _combinations.length; i++) {
        //     ttp_combinations[id].push(_combinations[i]);
        // }
        
    }

    function set_ttp_params(string memory _name, G.G1Point memory _ttp_pk, G.G1Point[] memory _hs) public onlyOwner {
        require (getMapTTPs(_name) == 0, "TTP name already exists.");
        setMapTTPs(_name);
        uint256 id = getMapTTPs(_name);
        for(uint256 i=0; i < _hs.length; i++) {
            ttp_hs[id].push(_hs[i]);
        }
        ttp_pk[id] = _ttp_pk;
    }
        
    function get_hs(string memory _name) public view returns (G.G1Point[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return hs[id];
    }

    function get_public_m_encoding(string memory _name) public view returns (uint256[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return public_m_encoding[id];
    }

    function get_alpha(string memory _name) public view returns (G.G2Point memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return alpha[id];
    }
    
    function get_beta(string memory _name) public view returns (G.G2Point[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return beta[id];
    }

    function get_g1_beta(string memory _name) public view returns (G.G1Point[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return g1_beta[id];
    }
    
    function get_opk(string memory _name) public view returns (G.G2Point[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return opk[id];
    }
    function get_bpk(string memory _name) public view returns (G.G1Point[] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        return beaver_public_key[id];
    }
    // function checkCombination(uint256 id, string[] memory combination) public view returns(bool) {
    //     string[][] memory all_combinations = ttp_combinations[id];
    //     for(uint256 i = 0; i < all_combinations.length; i++ ) {
    //         if(all_combinations[i].length == combination.length) {
    //             uint256 j = 0;
    //             for(j = 0; j < combination.length; j++ ) {
    //                 if (keccak256(bytes(all_combinations[i][j])) != keccak256(bytes(combination[j]))) {
    //                     break;
    //                 }
    //             }
    //             if ( j == combination.length) {
    //                 return true;
    //             }
    //         }
    //     }
    //     return false;
    // }

    function get_include_indexes(string memory _name, string[] memory combination) public view returns(uint256[][] memory) {
        uint256 id = getMapCredentials(_name);
        require(id != 0, "No such AC.");
        //require(checkCombination(id, combination), "Such a combination is not possible.");
        uint256[][] memory _include_indexes = new uint256[][](combination.length);
        for(uint256 i = 0; i < combination.length; i++ ) {
            _include_indexes[i] = new uint256[](include_indexes[id][combination[i]].length); 
            _include_indexes[i] = include_indexes[id][combination[i]];
        }
        return _include_indexes;
    }

    // function get_ttp_combinations(string memory _name) public view returns(string[][] memory) {
    //     uint256 id = getMapCredentials(_name);
    //     require(id != 0, "No such AC.");
    //     return ttp_combinations[id];
    // }

    function get_ttpKeys(string memory _name) public view returns(G.G1Point memory) {
        uint256 id = getMapTTPs(_name);
        require(id != 0, "No such TTP.");
        return ttp_pk[id];
    }

    function get_ttp_params(string memory _name) public view returns(G.G1Point[] memory) {
        uint256 id = getMapTTPs(_name);
        require(id != 0, "No such TTP");
        return ttp_hs[id];
    }

}