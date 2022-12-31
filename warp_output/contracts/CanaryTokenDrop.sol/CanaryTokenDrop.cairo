%lang starknet


from warplib.maths.external_input_check_ints import warp_external_input_check_int256
from warplib.maths.external_input_check_address import warp_external_input_check_address
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_contract_address, get_caller_address
from warplib.maths.ge import warp_ge256
from warplib.maths.div import warp_div256
from warplib.maths.eq import warp_eq


func WS0_READ_felt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) ->(val: felt){
    alloc_locals;
    let (read0) = WARP_STORAGE.read(loc);
    return (read0,);
}

func WS_WRITE0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt, value: felt) -> (res: felt){
    WARP_STORAGE.write(loc, value);
    return (value,);
}


// Contract Def CanaryTokenDrop


@event
func Droped_2b84f454(claimer : felt, amount_claimed : Uint256){
}

namespace CanaryTokenDrop{

    // Dynamic variables - Arrays and Maps

    // Static variables

    const __warp_0_canary = 0;

    const __warp_1_l2Eth = 1;

    const __warp_2_owner = 2;


    func __warp_constructor_0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_3__canary : felt, __warp_4__l2Eth : felt, __warp_5__owner : felt)-> (){
    alloc_locals;


        
        WS_WRITE0(__warp_0_canary, __warp_3__canary);
        
        WS_WRITE0(__warp_1_l2Eth, __warp_4__l2Eth);
        
        WS_WRITE0(__warp_2_owner, __warp_5__owner);
        
        
        
        return ();

    }

}


    @external
    func drop{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_6__amount : Uint256)-> (){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_6__amount);
        
        let (__warp_se_0) = WS0_READ_felt(CanaryTokenDrop.__warp_0_canary);
        
        let (__warp_se_1) = get_contract_address();
        
        let (__warp_pse_0) = Token_warped_interface.balanceOf(__warp_se_0, __warp_se_1);
        
        let (__warp_se_2) = warp_ge256(__warp_pse_0, __warp_6__amount);
        
        with_attr error_message("not enough to drop"){
            assert __warp_se_2 = 1;
        }
        
        let (__warp_7_amountToPay) = warp_div256(__warp_6__amount, Uint256(low=5, high=0));
        
        let (__warp_se_3) = WS0_READ_felt(CanaryTokenDrop.__warp_1_l2Eth);
        
        let (__warp_se_4) = get_caller_address();
        
        let (__warp_se_5) = get_contract_address();
        
        Token_warped_interface.transferFrom(__warp_se_3, __warp_se_4, __warp_se_5, __warp_7_amountToPay);
        
        let (__warp_se_6) = WS0_READ_felt(CanaryTokenDrop.__warp_0_canary);
        
        let (__warp_se_7) = get_caller_address();
        
        Token_warped_interface.transfer(__warp_se_6, __warp_se_7, __warp_6__amount);
        
        
        
        return ();

    }


    @external
    func withdrawFunds{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}()-> (){
    alloc_locals;


        
        let (__warp_se_8) = get_caller_address();
        
        let (__warp_se_9) = WS0_READ_felt(CanaryTokenDrop.__warp_2_owner);
        
        let (__warp_se_10) = warp_eq(__warp_se_8, __warp_se_9);
        
        with_attr error_message("Only owner"){
            assert __warp_se_10 = 1;
        }
        
        let (__warp_se_11) = WS0_READ_felt(CanaryTokenDrop.__warp_0_canary);
        
        let (__warp_se_12) = get_contract_address();
        
        let (__warp_8_balance) = Token_warped_interface.balanceOf(__warp_se_11, __warp_se_12);
        
        let (__warp_se_13) = WS0_READ_felt(CanaryTokenDrop.__warp_0_canary);
        
        let (__warp_se_14) = WS0_READ_felt(CanaryTokenDrop.__warp_2_owner);
        
        Token_warped_interface.transfer(__warp_se_13, __warp_se_14, __warp_8_balance);
        
        
        
        return ();

    }


    @view
    func owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}()-> (__warp_9 : felt){
    alloc_locals;


        
        let (__warp_se_15) = WS0_READ_felt(CanaryTokenDrop.__warp_2_owner);
        
        
        
        return (__warp_se_15,);

    }


    @constructor
    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_3__canary : felt, __warp_4__l2Eth : felt, __warp_5__owner : felt){
    alloc_locals;
    WARP_USED_STORAGE.write(3);


        
        warp_external_input_check_address(__warp_5__owner);
        
        warp_external_input_check_address(__warp_4__l2Eth);
        
        warp_external_input_check_address(__warp_3__canary);
        
        CanaryTokenDrop.__warp_constructor_0(__warp_3__canary, __warp_4__l2Eth, __warp_5__owner);
        
        
        
        return ();

    }

@storage_var
func WARP_STORAGE(index: felt) -> (val: felt){
}
@storage_var
func WARP_USED_STORAGE() -> (val: felt){
}
@storage_var
func WARP_NAMEGEN() -> (name: felt){
}
func readId{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) -> (val: felt){
    alloc_locals;
    let (id) = WARP_STORAGE.read(loc);
    if (id == 0){
        let (id) = WARP_NAMEGEN.read();
        WARP_NAMEGEN.write(id + 1);
        WARP_STORAGE.write(loc, id + 1);
        return (id + 1,);
    }else{
        return (id,);
    }
}


// Contract Def Token@interface


@contract_interface
namespace Token_warped_interface{
func balanceOf(_owner : felt)-> (balance : Uint256){
}
func transfer(_to : felt, _value : Uint256)-> (success : felt){
}
func transferFrom(_from : felt, _to : felt, _value : Uint256)-> (success : felt){
}
}