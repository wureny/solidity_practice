// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";


/**
 * @title ERC20Permit
 * @author wureny 
 * @dev 扩展了erc20的接口，通过permit函数实现了用签名来授权，少去用户调用erc20合约中approve函数的步骤，节省了gas费用；
 */
contract ERC20Permit is IERC20Permit ,ERC20,EIP712 {

    /**
     * @dev 记录每一位用户对应的nounces值
     */
    mapping (address => uint) private _nonces;

    /**
     * @dev permit函数的类型哈希
     */
    bytes32 private constant _PERMIT_TYPEHASH=keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /**
     * @dev 初始化 EIP712 的 name 以及 ERC20 的 name 和 symbol
     */
    constructor(string memory name, string memory symbol) EIP712(name, "1") ERC20(name, symbol){}

    /**
     * @dev 核心函数permit
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual override {
        //deadline必须是未来的时间
        require(block.timestamp<=deadline,"ERC20Permit Expired Time!");
        // 拼接 Hash
        bytes32 structHash = keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));
        bytes32 hash = _hashTypedDataV4(structHash);
        // 从签名和消息计算 signer，并验证签名
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");
        // 授权
        _approve(owner, spender, value);
    }

    /**
     * @dev 返回nonces值
     */
    function nonces(address owner) public view virtual override returns (uint256) {
        return _nonces[owner];
    }

    /**
     * @dev 返回域名分割符
     */
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev "消费nonce": 返回 `owner` 当前的 `nonce`，并增加 1。
     */
    function _useNonce(address owner) internal virtual returns (uint256 current) {
        current = _nonces[owner];
        _nonces[owner] += 1;
    }

}
