// SPDX-License-Identifier: MIT
pragma solidity ^0.8.8;
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./utils/Signature.sol";

contract ZKDocument is OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using Signature for bytes32;

    event DocumentCreated(
        address owner,
        string name,
        string uri,
        bytes32 documentHash,
        uint256 id,
        uint256 minFieldVerify,
        uint256 tokenId
    );

    event AddFieldVerify(
        uint256 tokenId,
        bytes32[] fieldHash,
        address[] verifiers
    );

    event SetVerifier(address[] verifiers, bool remove);

    event FieldVerified(uint256 tokenId, bytes32 fieldHash, address attestor);

    event DocumentVerified(uint256 tokenId, address verifier);

    enum DocumentStatus {
        PENDING,
        CONFIRMING,
        VERIFIED
    }

    struct Document {
        address owner;
        string name;
        string uri;
        bytes32 documentHash;
        uint256 minFieldVerify;
        uint256 fieldVerified;
        uint256 id;
        DocumentStatus status;
    }

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    uint256 public currentId;
    mapping(uint256 => Document) public documents;
    mapping(uint256 => mapping(bytes32 => address)) public verifierFields;
    mapping(uint256 => mapping(bytes32 => bool)) public fieldVerified;
    mapping(uint256 => uint256) public ids;
    mapping(address => bool) public verifiers;

    modifier onlyOnwerToken(uint256 _tokenId) {
        address sender = _msgSender();

        Document memory document = documents[_tokenId];
        require(document.owner != address(0), "document not found");
        require(document.owner == sender, "must be owner of token");
        _;
    }

    modifier onlyVerifier() {
        address sender = _msgSender();
        require(verifiers[sender], "must be verifier");
        _;
    }

    function initialize() external initializer {
        __ReentrancyGuard_init();
        __Ownable_init();
    }

    function setVerifier(address[] memory _verifiers, bool _remove)
        external
        onlyOwner
    {
        for (uint256 i = 0; i < _verifiers.length; i++) {
            if (_remove) {
                delete verifiers[_verifiers[i]];
            } else {
                verifiers[_verifiers[i]] = true;
            }
        }

        emit SetVerifier(_verifiers, _remove);
    }

    function createDocument(
        uint256 _id,
        string calldata _name,
        string calldata _uri,
        bytes32 _documentHash,
        uint256 _mintFieldVerify,
        bytes32[] calldata _fieldHash,
        address[] calldata _verifiers
    ) external nonReentrant returns (uint256) {
        address sender = _msgSender();
        uint256 id = _id;
        require(_fieldHash.length == _verifiers.length, "array invalid");
        require(ids[id] == 0, "Id create already");

        _mint(sender, ++currentId);
        documents[currentId] = Document(
            sender,
            _name,
            _uri,
            _documentHash,
            _mintFieldVerify,
            0,
            id,
            DocumentStatus.PENDING
        );
        for (uint256 i = 0; i < _fieldHash.length; i++) {
            require(verifiers[_verifiers[i]], "attestor invalid");
            verifierFields[currentId][_fieldHash[i]] = _verifiers[i];
        }

        ids[id] = currentId;
        emit DocumentCreated(
            sender,
            _name,
            _uri,
            _documentHash,
            id,
            _mintFieldVerify,
            currentId
        );

        emit AddFieldVerify(currentId, _fieldHash, _verifiers);

        return currentId;
    }

    function addFieldToVerify(
        uint256 _tokenId,
        bytes32[] calldata _fieldHash,
        address[] calldata _verifiers
    ) external onlyOnwerToken(_tokenId) {
        Document memory document = documents[_tokenId];

        require(
            document.status == DocumentStatus.PENDING,
            "cannot change document processing"
        );
        require(_fieldHash.length == _verifiers.length, "array invalid");

        for (uint256 i = 0; i < _fieldHash.length; i++) {
            require(verifiers[_verifiers[i]], "attestor invalid");
            verifierFields[_tokenId][_fieldHash[i]] = _verifiers[i];
        }

        emit AddFieldVerify(_tokenId, _fieldHash, _verifiers);
    }

    function verify(
        uint256 _tokenId,
        bytes32 _fieldHash,
        bytes calldata _signature
    ) external nonReentrant {
        address sender = _msgSender();
        Document storage document = documents[_tokenId];
        require(document.owner != address(0), "document not found");

        require(
            verifierFields[_tokenId][_fieldHash] == sender,
            "dont have permission to verify this field"
        );

        require(!fieldVerified[_tokenId][_fieldHash], "field verified");

        fieldVerified[_tokenId][_fieldHash] = true;
        document.fieldVerified++;

        if (document.status == DocumentStatus.PENDING) {
            document.status = DocumentStatus.CONFIRMING;
        }

        emit FieldVerified(_tokenId, _fieldHash, sender);

        if (document.fieldVerified == document.minFieldVerify) {
            document.status = DocumentStatus.VERIFIED;
            emit DocumentVerified(_tokenId, _msgSender());
        }
    }

    function accept(uint256 _tokenId) external nonReentrant {
        Document storage document = documents[_tokenId];
        require(document.owner != address(0), "document not found");
        require(
            document.fieldVerified == document.minFieldVerify,
            "Dont enough verify from attestor"
        );

        document.status = DocumentStatus.VERIFIED;

        emit DocumentVerified(_tokenId, _msgSender());
    }

    function getUri(uint256 _tokenId) public view returns (string memory) {
        Document memory document = documents[_tokenId];
        require(document.owner != address(0), "document not found");

        return document.uri;
    }

    function getTokenIdByDocumentId(uint256 _id) public view returns (uint256) {
        return ids[_id];
    }

    function documentVerify(uint256 _tokenId) public view returns (bool) {
        Document memory document = documents[_tokenId];
        require(document.owner != address(0), "document not found");

        return document.status == DocumentStatus.VERIFIED;
    }

    function checkFieldVerify(uint256 _tokenId, bytes32 _fieldHash)
        public
        view
        returns (bool)
    {
        return fieldVerified[_tokenId][_fieldHash];
    }

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "address zero is not a valid owner");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "invalid token ID");
        return owner;
    }

    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "mint to the zero address");
        require(!_exists(tokenId), "token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }
}
