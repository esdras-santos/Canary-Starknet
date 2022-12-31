
# Canary: The rights protocol

## Protocol description

### Motivation

Canary is a rights protocol based on borrow and lending protocols but with Canary you can sell the rights to use your NFT media to other people just by setting a small daily fee, max number of right holders and max holding time. “But why would anyone want to buy rights to an NFT?” Maybe you already face some problems with too much competition for a super rare NFT, you can’t sell your NFT due to a lack of liquidity or you wanna try that cool NFT art in your social network profile but you don’t wanna pay full price for the token. “But what happens to the owner of the NFT?” The owner of the NFT will receive the daily fee he has set, i.e. the owner of the NFT will earn from the daily fee and from the appreciation of his item because the more an item sells, the more it will be desired by other collectors. The NFT owner can also define a total number of rights holders and thus create scarcity for the rights to his NFT and of course in future updates we will support a parallel rights market where rights holders will be able to sell their rights to other holders.

### How it works?

The Canary incentive Token: You can only buy rights in the Canary protocol using the Canary Tokens. This happens because in this way we can incentivize the social network platforms to accept the rights and in exchange receive tokens that have real value.

The NFT owner: Deposits his Token in the Canary protocol defining the daily price of the right over the midia of the NFT, the maximum number of rights tokens that will be minted (to create scarcity) and the maximum number of days that someone can hold a right. After the hold time of some holder has reached a end the NFT owner that has his NFT deposited on Canary can withdraw a royalty fee based on the amount that the right holder pay when he buys the right and the spot of that right holder becomes available again if the NFT owner doesn’t lock the availability of the NFT. To withdraw the NFT the owner needs to lock the NFT availability and no one else will be able to buy rights over that NFT, after the availability of the NFT gets locked he will need to wait until the last right holder ends his right period and then he can withdraw his NFT.

The Canary Protocol: Holds the NFT deposited, control the number of right holders over that NFT media (the number of right holders cannot surpass the maximum number of right holders defined by the NFT owner when the NFT was deposited), verify the rights to a specific platform and check if the rights are verified for a specific platform. Canary will take 5% as fee over the total royalty fee (the total royalty fee is a product of the right holder period times the daily fee of the right token).

The right holder: Has a rights token that can be used as a proof that he has the right to use the media of that NFT for a certain period of time, for that he just needs to define the number of days (cannot surpass the maximum right period defined by the NFT owner) he wants to use the rights token and pay the respective fee and then the right holder can use the media in any platform that validates/verify the rights.

The platform: In the context of Canary the platform is who will accept and validate/verify the rights tokens and for this we did an incentive model that will benefit any platform that validates the rights tokens (we will talk about how this model works below).

### The Incentive Model

The Canary incentive model was developed to incentivize platforms to accept rights tokens and work as follows.

 1 - The right holder calls the verify function.

 2 - Mark the token of the right holder as verified.

 3 - Mint an amount of Canary tokens to the platform based on the daily fee of the respective token divided by two.

The right token of a holder can be verified just once on the platform in his right period after that the platform can just check if the token is already verified. In this model the platform will act almost like miners minting new tokens for each right verified (the initial supply of the canary token is set to zero).

### Future Roadmap

1 - Token drop in the launch of the protocol to exchange ETH for some Canary tokens and start to use the protocol to buy some rights.

2 - Turn Canary into an upgradable protocol with an Warp'ed version of the Diamond proxy pattern

## Work done to Warp it

Warp traspiler is very simple tool to use so i don't have much problems to learn how to use it to warp my Solidity contracts. The only issues was with the adaptations to turn my contracts into "Warpable" (I'll describe bellow) and some bugs (I'll describe in the next section).

1 - The first adptation was to remove the `indexed` keyword from events

2 - The second adptation was to change `msg.value` keyword in functions for ERC20 contract calls since all the tokens in StarkNet are ERC20.

3 - The third adptation was in the not allowed conversion from `uint160` to `address` due to Warp change in address size to 251 bits, so I just convert my `uint256` directly to `address` without passing through the `uint160` conversion (this type of conversion is not allowed by the Solidity compiler). 

## Experience using Warp and suggested improvements

The Warp transpiler was much simple to use this time than the first time that I tried to use it, I don't know exactly whats is changed since the first time that I use it but now with the simplicity I could care less about how to use the transpiler and care more about my protocol and the adaptations that i needed to do in order to make my protocol "Warpable".

### Bugs

1 - The first bug was with the version `2.4.2` of Warp. In this bug I was having problems with missing modules when typing `warp version`, but the Warp team solve that in less than 2 hours and release the version `2.4.3` with the problem solved.

2 - The second bug was in the `warp deploy_account`. In this bug I was having problems with BadRequests when trying to access the StarkNet API, in this bug the Warp team guide me and we figure out that the problem was in my Python version, I was using the Python version `3.10` instead of `3.9`.

### Suggested improvements

1 - The first suggestion of improvement is in the casting stack `address(uint160(uint256(bytes32)))`, this casting stack is not allowed by the Warp traspiler due to a change in address size to 251 bits, so in this case the developer have to change the casting stack to `address(uint256(bytes32))` which is not an allowed conversion on the Solidity compiler. Improvement: would be good if in the Syntactic Analysis the transpiler just ignores the conversion to `uint160` when the next conversion is to `address`, so in this case the transpiler will consider `address(uint160(uint256(bytes32)))` as `address(uint256(bytes32))` and the developer will have to care a little less about adaptations in conversions and will still be able to compile the code with the Solidity compiler. 

2 - The second suggestion is the `msg.value` call. When an `require(msg.value >= valueOfSomething)` occurs we know that an ETH transfer happens, so in this case i think will be an great improvement to raplace that require for  `ETHERC20.transferFrom(caller, thisContract, valueOfSomething)` since ETH is an ERC20 on StarkNet. This don't cover all the situations where `msg.value` is used but i think his can be a great improvement.

## Testnet Deployment Links

Carary ptotocol: [0x041b5ce9b2cdc12360be3d4b1a623487206c6709f794e6278757fb8528634eec](https://goerli.voyager.online/contract/0x041b5ce9b2cdc12360be3d4b1a623487206c6709f794e6278757fb8528634eec)



Account address: 0x029c0a51cbd307e0cc98ed6ac9876bb2e6efc5078a012484cee1eea540867a77
Public key: 0x061b26a2133ac04e1c55a3801558d3d78cf562f26815503e46d64c3da5ec9e05


canary:
Contract class hash: 0x1469e259107827d003fe651f32f50b6123bdbde748cdeead960f9d548de6bf0
Transaction hash: 0x2d138db9310ea2ad8d687eaa12d72bf3afe49a3e6ec37dc329e2534a237928b

Contract address: 0x041b5ce9b2cdc12360be3d4b1a623487206c6709f794e6278757fb8528634eec
Transaction hash: 0x215eed32d17f15bbf1125a030a765bb34a2937e2cd1f140f465c76d6d3a673a

canaryTokenDrop:
Contract class hash: 0x30fbd3ac75de72474665bd32eb0ea5e9aaee77a52f9125a046fe77233c639f1
Transaction hash: 0x5a6d6a6c56209e1c10f54df09741dd2d1a517ae58b0002a08de929e1ec2440b

canaryTokne:
Contract class hash: 0x2826aaa4dfb0bff77b4a04040d19d5995053e7f6bc4d8b7fde9ef16815b602
Transaction hash: 0x113e89a9f5a279d3a0162f2d7105263de9adbfc63472918ad5989eecb275544