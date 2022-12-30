// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "hardhat/console.sol";

interface ERC721Metadata{
    function tokenURI(uint256 _tokenId) external view returns (string memory);
}

interface IERC721{
    function transferFrom(address _from, address _to, uint256 _tokenId) external payable;
}

interface Token{
    function mint(address _platform, uint256 _amount) external;
    function burn(address _platform, uint256 _amount) external;
    function transfer(address _to, uint256 _value) external returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
}

contract Canary{
    uint256 treasury;
    uint256 period;
    address governanceToken;
    address contractOwner;

    uint256[] availableRights;
    mapping (uint256=>uint256) highestDeadline;
    mapping (address=>uint256) dividends;
    // tracks price before approval of the proposal
    mapping (uint256=>uint256) beforeProposal;
    // return erc721 address and token id of given rightid
    mapping (uint256=>bytes32[]) rightsOrigin;
    mapping (uint256=>string) rightUri;
    // rightid and return daily price for rights
    mapping (uint256=>uint256) dailyPrice;
    // receive erc721 address, nftid and return the max number of renters that the nft could have
    mapping (uint256=>uint256) maxRightsHolders;
    // receive erc721 address, nftid and return maximum rental time in days
    mapping (uint256=>uint256) maxtime;
    mapping (address=>uint256[]) rightsOver;
    // receive address and return list of nfts that the address have rights over "[erc721address, nftid]"
    mapping (address=>uint256[]) properties;
    
    // receive erc721 address and nftid and return if is available
    mapping (uint256=>bool) isAvailable;
    // receive erc721 address and nftid and return owner
    mapping (uint256=>address) owner;
    // receive erc721 address and nftid and return list of addresse that have rights over it
    mapping (uint256=>address[]) rightHolders;
    // receive erc721 address, nftid, and rights buyer address and return deadline over that nft
    mapping (uint256=>mapping (address=>uint256)) deadline;
    // receive erc721 address, nftid, and rights buyer address and return rights period in days
    mapping (uint256=>mapping (address=>uint256)) rightsPeriod;

    mapping (uint256=>mapping (address=>mapping (address=>bool))) validated;

    event GetRight(uint256 _rightid, uint256 _period, address _who);
    event DepositedNFT(address _erc721, uint256 _nftid);
    event RoyaltiesWithdraw(address owner, uint256 amount);


    modifier isNFTOwner(uint256 _rightid){
        require(owner[_rightid] == msg.sender, "only the NFT Owner");
        _;
    }

    constructor(address _owner){
        contractOwner = _owner;
    }

    function getRights(uint256 _rightid, uint256 _period) external{
        require(isAvailable[_rightid],"NFT is not available");
        require(maxtime[_rightid] >= _period,"period is above the max period");
        require(maxRightsHolders[_rightid] > 0, "limit of right holders reached");
        require(rightsPeriod[_rightid][msg.sender] == 0,"already buy this right");
        require(_period > 0, "period is equal to 0");
        Token ct = Token(governanceToken);
        // take 5% of the right amount as fee
        maxRightsHolders[_rightid] = maxRightsHolders[_rightid] - 1;
        uint256 value = dailyPrice[_rightid] * _period;
        ct.transferFrom(msg.sender, address(this), value);
        treasury += value * 500 / 10000;
        
        rightsPeriod[_rightid][msg.sender] = _period;
        rightsOver[msg.sender].push(_rightid);
        deadline[_rightid][msg.sender] = block.timestamp + (1 days * _period);
        
        if(block.timestamp + (1 days * _period) > highestDeadline[_rightid]){
            highestDeadline[_rightid] = block.timestamp + (1 days * _period);
        }
        rightHolders[_rightid].push(msg.sender);
        
        emit GetRight(_rightid, _period, msg.sender);
    }

    // need to call approval before calling this function
    function depositNFT(
        address _erc721, 
        uint256 _nftid, 
        uint256 _dailyPrice, 
        uint256 _maxPeriod,
        uint256 _amount) 
        external 
    {
        require(_erc721 != address(0x00), "collection address is zero");
        ERC721Metadata e721metadata = ERC721Metadata(_erc721);
        string memory uri = e721metadata.tokenURI(_nftid);
        _mint(_erc721, _nftid, _amount, _dailyPrice, _maxPeriod, uri);
        IERC721 e721 = IERC721(_erc721);
        e721.transferFrom(msg.sender, address(this), _nftid);
        emit DepositedNFT(_erc721, _nftid);
    }

    // due to his high complexity (O(N^2)) this function is only viable in StarkNet
    function withdrawRoyalties(
        uint256 _rightid) 
        external isNFTOwner(_rightid)
    {
        
        require(rightHolders[_rightid].length > 0, "right does not exists");
        uint256 amountToWithdraw = 0;
        uint256 j = 0;
        Token ct = Token(governanceToken);
        
        while(rightHolders[_rightid].length > 0){
            uint256 dl = deadline[_rightid][rightHolders[_rightid][j]];
            uint256 rp = rightsPeriod[_rightid][rightHolders[_rightid][j]];
            if(dl < block.timestamp){
                uint256 amount = (dailyPrice[_rightid] * rp);
                // subtract the fee
                amountToWithdraw += amount - (amount * 500 / 10000);  
                for(uint256 i; i < rightsOver[rightHolders[_rightid][j]].length; i++){
                    if(rightsOver[rightHolders[_rightid][j]][i] == _rightid){
                        rightsOver[rightHolders[_rightid][j]][i] = rightsOver[rightHolders[_rightid][j]][rightsOver[rightHolders[_rightid][j]].length -1];
                        rightsOver[rightHolders[_rightid][j]].pop();  
                        break;          
                    }
                } 
                deadline[_rightid][rightHolders[_rightid][j]] = 0;
                rightsPeriod[_rightid][rightHolders[_rightid][j]] = 0;

                rightHolders[_rightid][j] = rightHolders[_rightid][rightHolders[_rightid].length -1];  
                rightHolders[_rightid].pop();

                maxRightsHolders[_rightid] = maxRightsHolders[_rightid] + 1;
            }
        }
        emit RoyaltiesWithdraw(msg.sender, amountToWithdraw);
        ct.transfer(msg.sender, amountToWithdraw);
    }

    function withdrawNFT(uint256 _rightid) external isNFTOwner(_rightid) {
        require(highestDeadline[_rightid] < block.timestamp, "highest right deadline should end before withdraw");
        require(isAvailable[_rightid] == false, "NFT should be unavailable");
        
        uint256 _rightIndex;
        for(uint256 i; i< properties[msg.sender].length; i++){
            if(properties[msg.sender][i] == _rightid){
                _rightIndex = i;
                break;
            }
        }

        // conversion not allowed from "uint160" to "address" due to Warp change in address size to 251 bits
        // so the conversion will be from "uint256" to "address"
        address erc721 = address(uint160(uint256(rightsOrigin[_rightid][0])));
        uint256 nftid = uint256(rightsOrigin[_rightid][1]);
        _burn(_rightid, _rightIndex);
        highestDeadline[_rightid] = 0;
        IERC721 e721 = IERC721(erc721);
        e721.transferFrom(address(this), msg.sender, nftid);
    }

    function setAvailability( 
        uint256 _rightid, 
        bool _available) 
        external isNFTOwner(_rightid) 
    {
        
        uint256 _nftindex;
        for(uint256 i;i<availableRights.length-1;i++){
            if(availableRights[i]  == _rightid){
                _nftindex = i;
                break;
            }
        }
        if(_available == false){
            availableRights[_nftindex] = availableRights[availableRights.length - 1];
            availableRights.pop();
        } else {
            availableRights.push(_rightid);
        }
        isAvailable[_rightid] = _available;
    }

    function verifyRight(uint256 _rightid, address _platform) external{
        
        require(rightsPeriod[_rightid][_platform] == 0, "the platform cannot be the right holder");
        require(rightsPeriod[_rightid][msg.sender] > 0, "sender is not the right holder");
        require(deadline[_rightid][msg.sender] > block.timestamp,"has exceeded the right time");
        require(validated[_rightid][_platform][msg.sender] == false, "rightid and right holder are already validated");
        validated[_rightid][_platform][msg.sender] = true;
        Token ct = Token(governanceToken);
        ct.mint(_platform, dailyPrice[_rightid]/2);
    }

    function verified(uint256 _rightid, address _platform) external view returns(bool){
        
        return validated[_rightid][_platform][msg.sender];
    }

    function _mint(
        address _erc721, 
        uint256 _nftid, 
        uint256 _amount,
        uint256 _dailyPrice,
        uint256 _maxPeriod, 
        string memory _nftUri) 
        internal 
    {
        
        uint256 rightid = uint256(keccak256(abi.encode(_erc721, _nftid)));
        maxRightsHolders[rightid] = _amount;
        dailyPrice[rightid] = _dailyPrice;
        maxtime[rightid] = _maxPeriod;
        owner[rightid] = msg.sender;
        // conversion not allowed from "uint160" to "address" due to Warp change in address size to 251 bits
        // so the conversion will be from "uint256" to "address"
        rightsOrigin[rightid].push(bytes32(uint256(uint160(_erc721))));
        rightsOrigin[rightid].push(bytes32(_nftid));
        rightUri[rightid] = _nftUri;
        isAvailable[rightid] = true;
        properties[msg.sender].push(rightid);
        availableRights.push(rightid);
    }

    function _burn(uint256 _rightid, uint256 _rightIndex) internal{
        
        maxRightsHolders[_rightid] = 0;
        dailyPrice[_rightid] = 0;
        maxtime[_rightid] = 0;
        rightsOrigin[_rightid].pop();
        rightsOrigin[_rightid].pop();
        properties[msg.sender][_rightIndex] = properties[msg.sender][properties[msg.sender].length - 1];
        properties[msg.sender].pop();
        rightUri[_rightid] = "";
        owner[_rightid] = address(0x00);
    }

    function setGovernanceToken(address _newToken) external{
        require(contractOwner == msg.sender);
        governanceToken = _newToken;
    }

    function currentTreasury() external view returns (uint256){
        
        return treasury;
    }

    function dailyPriceOf(uint256 _rightid) external view returns (uint256) {
        
        return dailyPrice[_rightid];
    }

    function availableRightsOf(uint256 _rightid) external view returns (uint256) {
        
        return maxRightsHolders[_rightid];
    }

    function maxPeriodOf(uint256 _rightid) external view returns (uint256) {
        
        return maxtime[_rightid];
    }

    function rightsPeriodOf(uint256 _rightid, address _holder) external view returns (uint256){
        
        return rightsPeriod[_rightid][_holder];
    }

    function rightsOf(address _rightsHolder) external view returns (uint256[] memory) {
        
        return rightsOver[_rightsHolder];
    }

    function propertiesOf(address _owner) external view returns (uint256[] memory) {
        
        return properties[_owner];
    }

    function getAvailableNFTs() external view returns (uint256[] memory) {
        
        return availableRights;
    }

    function rightHoldersOf(uint256 _rightid) external view returns (address[] memory){
        
        return rightHolders[_rightid];
    }

    function holderDeadline(uint256 _rightid, address _holder) external view returns (uint256){
        
        return deadline[_rightid][_holder];
    }

    function ownerOf(uint256 _rightid) external view returns (address){
        
        return owner[_rightid];
    }

    function availabilityOf(uint256 _rightid) external view returns (bool){
        
        return isAvailable[_rightid];
    }

    function rightURI(uint256 _rightid) external view returns (string memory){
        
        return rightUri[_rightid];
    }

    function originOf(uint256 _rightid) external view returns (bytes32[] memory){
        
        return rightsOrigin[_rightid];
    }
}

