// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {Params} from "./Params.sol";

contract Opening {

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

    mapping(address => bool) private openers;
    function addOpener(address opener_address) public onlyOwner {
        openers[opener_address] = true;
    }
    function removeOpener(address opener_address) public onlyOwner {
        openers[opener_address] = false;
    }
    modifier onlyOpeners {
        require(openers[msg.sender]);
        _;
    }
    
    event emitOpening(uint256 indexed id, uint256 opening_session_id, address opener_address, uint256[13][] openingshares);
    function SendOpeningInfo(string memory name, uint256 opening_session_id,  uint256[13][] memory openingshares) public onlyOpeners {
        uint256 id = params.getMapCredentials(name);
        require(id != 0, "No such AC.");
        emit emitOpening(id, opening_session_id, msg.sender, openingshares);
    }
}