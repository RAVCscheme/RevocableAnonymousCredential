// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {Params} from "./Params.sol";

contract Issue {

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

    mapping(address => bool) private issuers;
    function addIssuer(address issuer_address) public onlyOwner {
        issuers[issuer_address] = true;
    }
    function removeIssuer(address issuer_address) public onlyOwner {
        issuers[issuer_address] = false;
    }
    modifier onlyIssuers {
        require(issuers[msg.sender]);
        _;
    }

    event emitIssue(uint256 indexed id, address indexed receiver, address issuer_address, uint256[2] h, uint256[2] t);
    event get_ya_shares(uint256 id);
    function SendBlindSign(string memory name, address receiver, uint256[2] memory h, uint256[2] memory t) public onlyIssuers {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        emit emitIssue(id, receiver, msg.sender, h, t);
    }
    function get_kr_W(string memory name) public {
        uint256 id = params.getMapCredentials(name);
        emit get_ya_shares(id);
    }
}