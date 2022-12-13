%lang starknet

from warplib.memory import wm_alloc, wm_write_256, wm_dyn_array_length, wm_new
from starkware.cairo.common.uint256 import Uint256, uint256_sub, uint256_lt, uint256_eq, uint256_add
from starkware.cairo.common.dict import dict_write, dict_read
from warplib.maths.utils import narrow_safe, felt_to_uint256, uint256_to_address_felt
from warplib.maths.int_conversions import warp_uint256
from starkware.cairo.common.alloc import alloc
from warplib.maths.external_input_check_ints import warp_external_input_check_int256
from warplib.maths.external_input_check_address import warp_external_input_check_address
from warplib.maths.external_input_check_bool import warp_external_input_check_bool
from warplib.dynamic_arrays_util import (
    fixed_bytes256_to_felt_dynamic_array,
    felt_array_to_warp_memory_array,
)
from starkware.cairo.common.cairo_builtins import HashBuiltin, BitwiseBuiltin
from warplib.maths.gt import warp_gt256
from warplib.block_methods import warp_block_timestamp
from warplib.maths.lt import warp_lt256
from warplib.maths.mul import warp_mul256
from warplib.maths.div import warp_div256
from warplib.maths.sub import warp_sub256
from warplib.maths.add import warp_add256
from warplib.maths.eq import warp_eq256, warp_eq
from starkware.starknet.common.syscalls import get_caller_address, get_contract_address
from starkware.cairo.common.dict_access import DictAccess
from warplib.maths.ge import warp_ge256
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from warplib.maths.neq import warp_neq
from warplib.keccak import warp_keccak

struct cd_dynarray_felt{
    len : felt,
    ptr : felt*,
}

struct cd_dynarray_Uint256{
    len : felt,
    ptr : Uint256*,
}

func WM0_d_arr{range_check_ptr, warp_memory : DictAccess*}() -> (loc : felt){
    alloc_locals;
    let (start) = wm_alloc(Uint256(0x2, 0x0));
    wm_write_256{warp_memory=warp_memory}(start, Uint256(0x0, 0x0));
    return (start);
}

func wm_to_storage0_elem{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    warp_memory : DictAccess*,
}(storage_name : felt, mem_loc : felt, length : Uint256) -> (){
    alloc_locals;
    if(length.low == 0){
        if(length.high == 0){
            return ();
        }
    }
    let (index) = uint256_sub(length, Uint256(1, 0));
    let (storage_loc) = WARP_DARRAY0_felt.read(storage_name, index);
    let mem_loc = mem_loc - 1;
    if(storage_loc == 0){
        let (storage_loc) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(storage_loc + 1);
        WARP_DARRAY0_felt.write(storage_name, index, storage_loc);
        let (copy) = dict_read{dict_ptr=warp_memory}(mem_loc);
        WARP_STORAGE.write(storage_loc, copy);
        return wm_to_storage0_elem(storage_name, mem_loc, index);
    }else{
        let (copy) = dict_read{dict_ptr=warp_memory}(mem_loc);
        WARP_STORAGE.write(storage_loc, copy);
        return wm_to_storage0_elem(storage_name, mem_loc, index);
    }
}
func wm_to_storage0{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    warp_memory : DictAccess*,
}(loc : felt, mem_loc : felt) -> (loc : felt){
    alloc_locals;
    let (length) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (mem_length) = wm_dyn_array_length(mem_loc);
    WARP_DARRAY0_felt_LENGTH.write(loc, mem_length);
    let (narrowedLength) = narrow_safe(mem_length);
    wm_to_storage0_elem(loc, mem_loc + 2 + 1 * narrowedLength, mem_length);
    let (lesser) = uint256_lt(mem_length, length);
    if( lesser == 1){
        WS2_DYNAMIC_ARRAY_DELETE_elem(loc, mem_length, length);
        return (loc);
    }else{
        return (loc);
    }
}

func WS0_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
){
    WARP_STORAGE.write(loc, 0);
    return ();
}

func WS1_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
){
    WARP_STORAGE.write(loc, 0);
    WARP_STORAGE.write(loc + 1, 0);
    return ();
}

func WS2_DYNAMIC_ARRAY_DELETE_elem{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt, index : Uint256, length : Uint256){
    alloc_locals;
    let (stop) = uint256_eq(index, length);
    if( stop == 1){
        return ();
    }
    let (elem_loc) = WARP_DARRAY0_felt.read(loc, index);
    WS3_DELETE(elem_loc);
    let (next_index, _) = uint256_add(index, Uint256(0x1, 0x0));
    return WS2_DYNAMIC_ARRAY_DELETE_elem(loc, next_index, length);
}
func WS2_DYNAMIC_ARRAY_DELETE{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt){
    alloc_locals;
    let (length) = WARP_DARRAY0_felt_LENGTH.read(loc);
    WARP_DARRAY0_felt_LENGTH.write(loc, Uint256(0x0, 0x0));
    return WS2_DYNAMIC_ARRAY_DELETE_elem(loc, Uint256(0x0, 0x0), length);
}

func WS3_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
){
    WARP_STORAGE.write(loc, 0);
    return ();
}

func WARP_DARRAY0_felt_IDX{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(ref : felt, index : Uint256) -> (res : felt){
    alloc_locals;
    let (length) = WARP_DARRAY0_felt_LENGTH.read(ref);
    let (inRange) = uint256_lt(index, length);
    assert inRange = 1;
    let (existing) = WARP_DARRAY0_felt.read(ref, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_DARRAY0_felt.write(ref, index, used);
        return (used);
    }else{
        return (existing);
    }
}

func WARP_DARRAY1_Uint256_IDX{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(ref : felt, index : Uint256) -> (res : felt){
    alloc_locals;
    let (length) = WARP_DARRAY1_Uint256_LENGTH.read(ref);
    let (inRange) = uint256_lt(index, length);
    assert inRange = 1;
    let (existing) = WARP_DARRAY1_Uint256.read(ref, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(ref, index, used);
        return (used);
    }else{
        return (existing);
    }
}

func WARP_DARRAY0_felt_POP{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (isEmpty) = uint256_eq(len, Uint256(0, 0));
    assert isEmpty = 0;
    let (newLen) = uint256_sub(len, Uint256(1, 0));
    WARP_DARRAY0_felt_LENGTH.write(loc, newLen);
    let (elem_loc) = WARP_DARRAY0_felt.read(loc, newLen);
    return WS0_DELETE(elem_loc);
}

func WARP_DARRAY1_Uint256_POP{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (isEmpty) = uint256_eq(len, Uint256(0, 0));
    assert isEmpty = 0;
    let (newLen) = uint256_sub(len, Uint256(1, 0));
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, newLen);
    return WS1_DELETE(elem_loc);
}

func WARP_DARRAY1_Uint256_PUSHV0{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    bitwise_ptr : BitwiseBuiltin*,
}(loc : felt, value : Uint256) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1, 0));
    assert carry = 0;
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY1_Uint256.read(loc, len);
    if( (existing) == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(loc, len, used);
        WS_WRITE0(used, value);
    }else{
        WS_WRITE0(existing, value);
    }
    return ();
}

func WARP_DARRAY0_felt_PUSHV1{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    bitwise_ptr : BitwiseBuiltin*,
}(loc : felt, value : felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1, 0));
    assert carry = 0;       
    WARP_DARRAY0_felt_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY0_felt.read(loc, len);
    if( (existing) == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_DARRAY0_felt.write(loc, len, used);
        WS_WRITE1(used, value);
    }else{
        WS_WRITE1(existing, value);
    }
    return ();
}

func WARP_DARRAY1_Uint256_PUSHV2{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    bitwise_ptr : BitwiseBuiltin*,
}(loc : felt, value : Uint256) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1, 0));
    assert carry = 0;
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY1_Uint256.read(loc, len);
    if( (existing) == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(loc, len, used);
        WS_WRITE0(used, value);
    }else{
        WS_WRITE0(existing, value);
    }
    return ();
}

func WS0_READ_warp_id{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
) -> (val : felt){
    alloc_locals;
    let (read0) = readId(loc);
    return (read0);
}

func WS1_READ_Uint256{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
) -> (val : Uint256){
    alloc_locals;
    let (read0) = WARP_STORAGE.read(loc);
    let (read1) = WARP_STORAGE.read(loc + 1);
    return (Uint256(low=read0, high=read1));
}

func WS2_READ_felt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
) -> (val : felt){
    alloc_locals;
    let (read0) = WARP_STORAGE.read(loc);
    return (read0);
}

func ws_dynamic_array_to_calldata0_write{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt, index : felt, len : felt, ptr : Uint256*) -> (ptr : Uint256*){
    alloc_locals;
    if( len == index){
        return (ptr);
    }
    let (index_uint256) = warp_uint256(index);
    let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, index_uint256);
    let (elem) = WS1_READ_Uint256(elem_loc);
    assert ptr[index] = elem;
    return ws_dynamic_array_to_calldata0_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata0{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (dyn_array_struct : cd_dynarray_Uint256){
    alloc_locals;
    let (len_uint256) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let len = len_uint256.low + len_uint256.high * 128;
    let (ptr : Uint256*) = alloc();
    let (ptr : Uint256*) = ws_dynamic_array_to_calldata0_write(loc, 0, len, ptr);
    let dyn_array_struct = cd_dynarray_Uint256(len, ptr);
    return (dyn_array_struct);
}

func ws_dynamic_array_to_calldata1_write{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt, index : felt, len : felt, ptr : felt*) -> (ptr : felt*){
    alloc_locals;
    if( len == index){
        return (ptr);
    }
    let (index_uint256) = warp_uint256(index);
    let (elem_loc) = WARP_DARRAY0_felt.read(loc, index_uint256);
    let (elem) = WS2_READ_felt(elem_loc);
    assert ptr[index] = elem;
    return ws_dynamic_array_to_calldata1_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata1{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (dyn_array_struct : cd_dynarray_felt){
    alloc_locals;
    let (len_uint256) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let len = len_uint256.low + len_uint256.high * 128;
    let (ptr : felt*) = alloc();
    let (ptr : felt*) = ws_dynamic_array_to_calldata1_write(loc, 0, len, ptr);
    let dyn_array_struct = cd_dynarray_felt(len, ptr);
    return (dyn_array_struct);
}

func ws_dynamic_array_to_calldata2_write{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt, index : felt, len : felt, ptr : felt*) -> (ptr : felt*){
    alloc_locals;
    if( len == index){
        return (ptr);
    }
    let (index_uint256) = warp_uint256(index);
    let (elem_loc) = WARP_DARRAY0_felt.read(loc, index_uint256);
    let (elem) = WS2_READ_felt(elem_loc);
    assert ptr[index] = elem;
    return ws_dynamic_array_to_calldata2_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata2{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (dyn_array_struct : cd_dynarray_felt){
    alloc_locals;
    let (len_uint256) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let len = len_uint256.low + len_uint256.high * 128;
    let (ptr : felt*) = alloc();
    let (ptr : felt*) = ws_dynamic_array_to_calldata2_write(loc, 0, len, ptr);
    let dyn_array_struct = cd_dynarray_felt(len, ptr);
    return (dyn_array_struct);
}

func ws_dynamic_array_to_calldata3_write{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt, index : felt, len : felt, ptr : Uint256*) -> (ptr : Uint256*){
    alloc_locals;
    if( len == index){
        return (ptr);
    }
    let (index_uint256) = warp_uint256(index);
    let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, index_uint256);
    let (elem) = WS1_READ_Uint256(elem_loc);
    assert ptr[index] = elem;
    return ws_dynamic_array_to_calldata3_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata3{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(loc : felt) -> (dyn_array_struct : cd_dynarray_Uint256){
    alloc_locals;
    let (len_uint256) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let len = len_uint256.low + len_uint256.high * 128;
    let (ptr : Uint256*) = alloc();
    let (ptr : Uint256*) = ws_dynamic_array_to_calldata3_write(loc, 0, len, ptr);
    let dyn_array_struct = cd_dynarray_Uint256(len, ptr);
    return (dyn_array_struct);
}

func WS_WRITE0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt, value : Uint256
) -> (res : Uint256){
    WARP_STORAGE.write(loc, value.low);
    WARP_STORAGE.write(loc + 1, value.high);
    return (value);
}

func WS_WRITE1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt, value : felt
) -> (res : felt){
    WARP_STORAGE.write(loc, value);
    return (value);
}

func cd_to_memory0_elem{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    warp_memory : DictAccess*,
}(calldata : felt*, mem_start : felt, length : felt){
    alloc_locals;
    if( length == 0){
        return ();
    }
    dict_write{dict_ptr=warp_memory}(mem_start, calldata[0]);
    return cd_to_memory0_elem(calldata + 1, mem_start + 1, length - 1);
}
func cd_to_memory0{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr : felt,
    warp_memory : DictAccess*,
}(calldata : cd_dynarray_felt) -> (mem_loc : felt){
    alloc_locals;
    let (len256) = felt_to_uint256(calldata.len);
    let (mem_start) = wm_new(len256, Uint256(0x1, 0x0));
    cd_to_memory0_elem(calldata.ptr, mem_start + 2, calldata.len);
    return (mem_start);
}

func abi_encode0{bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(
    param0 : felt, param1 : Uint256
) -> (result_ptr : felt){
    alloc_locals;
    let bytes_index : felt = 0;
    let bytes_offset : felt = 64;
    let (bytes_array : felt*) = alloc();
    let (param0256) = felt_to_uint256(param0);
    fixed_bytes256_to_felt_dynamic_array(bytes_index, bytes_array, 0, param0256);
    let bytes_index = bytes_index + 32;
    fixed_bytes256_to_felt_dynamic_array(bytes_index, bytes_array, 0, param1);
    let bytes_index = bytes_index + 32;
    let (max_length256) = felt_to_uint256(bytes_offset);
    let (mem_ptr) = wm_new(max_length256, Uint256(0x1, 0x0));
    felt_array_to_warp_memory_array(0, bytes_array, 0, mem_ptr, bytes_offset);
    return (mem_ptr);
}

@storage_var
func WARP_DARRAY0_felt(name : felt, index : Uint256) -> (resLoc : felt){
}
@storage_var
func WARP_DARRAY0_felt_LENGTH(name : felt) -> (index : Uint256){
}

@storage_var
func WARP_DARRAY1_Uint256(name : felt, index : Uint256) -> (resLoc : felt){
}
@storage_var
func WARP_DARRAY1_Uint256_LENGTH(name : felt) -> (index : Uint256){
}

@storage_var
func WARP_MAPPING0(name : felt, index : Uint256) -> (resLoc : felt){
}
func WS0_INDEX_Uint256_to_warp_id{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : Uint256) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING0.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING0.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

@storage_var
func WARP_MAPPING1(name : felt, index : felt) -> (resLoc : felt){
}
func WS1_INDEX_felt_to_Uint256{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : felt) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING1.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_MAPPING1.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

@storage_var
func WARP_MAPPING2(name : felt, index : Uint256) -> (resLoc : felt){
}
func WS2_INDEX_Uint256_to_Uint256{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : Uint256) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING2.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_MAPPING2.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

@storage_var
func WARP_MAPPING3(name : felt, index : felt) -> (resLoc : felt){
}
func WS3_INDEX_felt_to_warp_id{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : felt) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING3.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING3.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

@storage_var
func WARP_MAPPING4(name : felt, index : Uint256) -> (resLoc : felt){
}
func WS4_INDEX_Uint256_to_felt{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : Uint256) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING4.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING4.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

@storage_var
func WARP_MAPPING5(name : felt, index : felt) -> (resLoc : felt){
}
func WS5_INDEX_felt_to_felt{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
}(name : felt, index : felt) -> (res : felt){
    alloc_locals;
    let (existing) = WARP_MAPPING5.read(name, index);
    if( existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING5.write(name, index, used);
        return (used);
    }else{
        return (existing);
    }
}

// Contract Def CanaryFacet

@event
func GetRight_4215fdfe(
    __warp_usrid21__rightid : Uint256, __warp_usrid22__period : Uint256, __warp_usrid23__who : felt
){
}

@event
func DepositedNFT_8b187cf9(__warp_usrid24__erc721 : felt, __warp_usrid25__nftid : Uint256){
}

@event
func RoyaltiesWithdraw_644800e6(__warp_usrid26_owner : felt, __warp_usrid27_amount : Uint256){
}

@storage_var
func WARP_STORAGE(index : felt) -> (val : felt){
}
@storage_var
func WARP_USED_STORAGE() -> (val : felt){
}
@storage_var
func WARP_NAMEGEN() -> (name : felt){
}
func readId{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
    loc : felt
) -> (val : felt){
    alloc_locals;
    let (id) = WARP_STORAGE.read(loc);
    if( id == 0){
        let (id) = WARP_NAMEGEN.read();
        WARP_NAMEGEN.write(id + 1);
        WARP_STORAGE.write(loc, id + 1);
        return (id + 1);
    }else{
        return (id);
    }
}

namespace CanaryFacet{
    // Dynamic variables - Arrays and Maps

    const __warp_usrid4_availableRights = 1;

    const __warp_usrid5_highestDeadline = 2;

    const __warp_usrid6_divids = 3;

    const __warp_usrid7_beforeProposal = 4;

    const __warp_usrid8_rightsOrigin = 5;

    const __warp_usrid9_rightUri = 6;

    const __warp_usrid10_dailyPrice = 7;

    const __warp_usrid11_maxRightsHolders = 8;

    const __warp_usrid12_maxtime = 9;

    const __warp_usrid13_rightsOver = 10;

    const __warp_usrid14_properties = 11;

    const __warp_usrid15_isAvailable = 12;

    const __warp_usrid16_owner = 13;

    const __warp_usrid17_rightHolders = 14;

    const __warp_usrid18_deadline = 15;

    const __warp_usrid19_rightsPeriod = 16;

    const __warp_usrid20_validated = 17;

    // Static variables

    const __warp_usrid0_treasury = 0;

    const __warp_usrid1_period = 2;

    const __warp_usrid2_governanceToken = 4;

    const __warp_usrid3_contractOwner = 5;

    func __warp_while1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ) -> (
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ){
        alloc_locals;

        let (__warp_se_0) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid17_rightHolders, __warp_usrid39__rightid
        );

        let (__warp_se_1) = WS0_READ_warp_id(__warp_se_0);

        let (__warp_se_2) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_1);

        let (__warp_se_3) = warp_gt256(__warp_se_2, Uint256(low=0, high=0));

        if( __warp_se_3 != 0){
            let (__warp_se_4) = WS0_INDEX_Uint256_to_warp_id(
                __warp_usrid18_deadline, __warp_usrid39__rightid
            );

            let (__warp_se_5) = WS0_READ_warp_id(__warp_se_4);

            let (__warp_se_6) = WS0_INDEX_Uint256_to_warp_id(
                __warp_usrid17_rightHolders, __warp_usrid39__rightid
            );

            let (__warp_se_7) = WS0_READ_warp_id(__warp_se_6);

            let (__warp_se_8) = WARP_DARRAY0_felt_IDX(__warp_se_7, __warp_usrid41_j);

            let (__warp_se_9) = WS2_READ_felt(__warp_se_8);

            let (__warp_se_10) = WS1_INDEX_felt_to_Uint256(__warp_se_5, __warp_se_9);

            let (__warp_usrid42_dl) = WS1_READ_Uint256(__warp_se_10);

            let (__warp_se_11) = WS0_INDEX_Uint256_to_warp_id(
                __warp_usrid19_rightsPeriod, __warp_usrid39__rightid
            );

            let (__warp_se_12) = WS0_READ_warp_id(__warp_se_11);

            let (__warp_se_13) = WS0_INDEX_Uint256_to_warp_id(
                __warp_usrid17_rightHolders, __warp_usrid39__rightid
            );

            let (__warp_se_14) = WS0_READ_warp_id(__warp_se_13);

            let (__warp_se_15) = WARP_DARRAY0_felt_IDX(__warp_se_14, __warp_usrid41_j);

            let (__warp_se_16) = WS2_READ_felt(__warp_se_15);

            let (__warp_se_17) = WS1_INDEX_felt_to_Uint256(__warp_se_12, __warp_se_16);

            let (__warp_usrid43_rp) = WS1_READ_Uint256(__warp_se_17);

            let (__warp_se_18) = warp_block_timestamp();

            let (__warp_se_19) = warp_lt256(__warp_usrid42_dl, __warp_se_18);

            if( __warp_se_19 != 0){
                let (__warp_se_20) = WS2_INDEX_Uint256_to_Uint256(
                    __warp_usrid10_dailyPrice, __warp_usrid39__rightid
                );

                let (__warp_se_21) = WS1_READ_Uint256(__warp_se_20);

                let (__warp_usrid44_amount) = warp_mul256(__warp_se_21, __warp_usrid43_rp);

                let (__warp_se_22) = warp_mul256(__warp_usrid44_amount, Uint256(low=500, high=0));

                let (__warp_se_23) = warp_div256(__warp_se_22, Uint256(low=10000, high=0));

                let (__warp_se_24) = warp_sub256(__warp_usrid44_amount, __warp_se_23);

                let (__warp_se_25) = warp_add256(__warp_usrid40_amountToWithdraw, __warp_se_24);

                let __warp_usrid40_amountToWithdraw = __warp_se_25;

                let __warp_usrid45_i = Uint256(low=0, high=0);

                let (__warp_tv_0, __warp_tv_1, __warp_tv_2) = __warp_while0(
                    __warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j
                );

                let __warp_usrid41_j = __warp_tv_2;

                let __warp_usrid39__rightid = __warp_tv_1;

                let __warp_usrid45_i = __warp_tv_0;

                let (__warp_se_26) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid18_deadline, __warp_usrid39__rightid
                );

                let (__warp_se_27) = WS0_READ_warp_id(__warp_se_26);

                let (__warp_se_28) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_29) = WS0_READ_warp_id(__warp_se_28);

                let (__warp_se_30) = WARP_DARRAY0_felt_IDX(__warp_se_29, __warp_usrid41_j);

                let (__warp_se_31) = WS2_READ_felt(__warp_se_30);

                let (__warp_se_32) = WS1_INDEX_felt_to_Uint256(__warp_se_27, __warp_se_31);

                WS_WRITE0(__warp_se_32, Uint256(low=0, high=0));

                let (__warp_se_33) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid19_rightsPeriod, __warp_usrid39__rightid
                );

                let (__warp_se_34) = WS0_READ_warp_id(__warp_se_33);

                let (__warp_se_35) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_36) = WS0_READ_warp_id(__warp_se_35);

                let (__warp_se_37) = WARP_DARRAY0_felt_IDX(__warp_se_36, __warp_usrid41_j);

                let (__warp_se_38) = WS2_READ_felt(__warp_se_37);

                let (__warp_se_39) = WS1_INDEX_felt_to_Uint256(__warp_se_34, __warp_se_38);

                WS_WRITE0(__warp_se_39, Uint256(low=0, high=0));

                let (__warp_se_40) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_41) = WS0_READ_warp_id(__warp_se_40);

                let (__warp_se_42) = WARP_DARRAY0_felt_IDX(__warp_se_41, __warp_usrid41_j);

                let (__warp_se_43) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_44) = WS0_READ_warp_id(__warp_se_43);

                let (__warp_se_45) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_46) = WS0_READ_warp_id(__warp_se_45);

                let (__warp_se_47) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_46);

                let (__warp_se_48) = warp_sub256(__warp_se_47, Uint256(low=1, high=0));

                let (__warp_se_49) = WARP_DARRAY0_felt_IDX(__warp_se_44, __warp_se_48);

                let (__warp_se_50) = WS2_READ_felt(__warp_se_49);

                WS_WRITE1(__warp_se_42, __warp_se_50);

                let (__warp_se_51) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_52) = WS0_READ_warp_id(__warp_se_51);

                WARP_DARRAY0_felt_POP(__warp_se_52);

                let (__warp_se_53) = WS2_INDEX_Uint256_to_Uint256(
                    __warp_usrid11_maxRightsHolders, __warp_usrid39__rightid
                );

                let (__warp_se_54) = WS2_INDEX_Uint256_to_Uint256(
                    __warp_usrid11_maxRightsHolders, __warp_usrid39__rightid
                );

                let (__warp_se_55) = WS1_READ_Uint256(__warp_se_54);

                let (__warp_se_56) = warp_add256(__warp_se_55, Uint256(low=1, high=0));

                WS_WRITE0(__warp_se_53, __warp_se_56);

                let (
                    __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
                ) = __warp_while1_if(_part2(
                    __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
                ));

                return (__warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw);
            }else{
                let (
                    __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
                ) = __warp_while1_if(_part2(
                    __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
                ));

                return (__warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw);
            }
        }else{
            let __warp_usrid39__rightid = __warp_usrid39__rightid;

            let __warp_usrid41_j = __warp_usrid41_j;

            let __warp_usrid40_amountToWithdraw = __warp_usrid40_amountToWithdraw;

            return (__warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw);
        }
    }

    func __warp_while1_if_part2{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ) -> (
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ){
        alloc_locals;

        let (
            __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
        ) = __warp_while1_if(_part1(
            __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
        ));

        return (__warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw);
    }

    func __warp_while1_if_part1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ) -> (
        __warp_usrid39__rightid : Uint256,
        __warp_usrid41_j : Uint256,
        __warp_usrid40_amountToWithdraw : Uint256,
    ){
        alloc_locals;

        let (
            __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
        ) = __warp_while1(
            __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
        );

        return (__warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw);
    }

    func __warp_while0{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ) -> (
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ){
        alloc_locals;

        let (__warp_se_57) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid17_rightHolders, __warp_usrid39__rightid
        );

        let (__warp_se_58) = WS0_READ_warp_id(__warp_se_57);

        let (__warp_se_59) = WARP_DARRAY0_felt_IDX(__warp_se_58, __warp_usrid41_j);

        let (__warp_se_60) = WS2_READ_felt(__warp_se_59);

        let (__warp_se_61) = WS3_INDEX_felt_to_warp_id(__warp_usrid13_rightsOver, __warp_se_60);

        let (__warp_se_62) = WS0_READ_warp_id(__warp_se_61);

        let (__warp_se_63) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_62);

        let (__warp_se_64) = warp_lt256(__warp_usrid45_i, __warp_se_63);

        if( __warp_se_64 != 0){
            let (__warp_se_65) = WS0_INDEX_Uint256_to_warp_id(
                __warp_usrid17_rightHolders, __warp_usrid39__rightid
            );

            let (__warp_se_66) = WS0_READ_warp_id(__warp_se_65);

            let (__warp_se_67) = WARP_DARRAY0_felt_IDX(__warp_se_66, __warp_usrid41_j);

            let (__warp_se_68) = WS2_READ_felt(__warp_se_67);

            let (__warp_se_69) = WS3_INDEX_felt_to_warp_id(__warp_usrid13_rightsOver, __warp_se_68);

            let (__warp_se_70) = WS0_READ_warp_id(__warp_se_69);

            let (__warp_se_71) = WARP_DARRAY1_Uint256_IDX(__warp_se_70, __warp_usrid45_i);

            let (__warp_se_72) = WS1_READ_Uint256(__warp_se_71);

            let (__warp_se_73) = warp_eq256(__warp_se_72, __warp_usrid39__rightid);

            if( __warp_se_73 != 0){
                let (__warp_se_74) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_75) = WS0_READ_warp_id(__warp_se_74);

                let (__warp_se_76) = WARP_DARRAY0_felt_IDX(__warp_se_75, __warp_usrid41_j);

                let (__warp_se_77) = WS2_READ_felt(__warp_se_76);

                let (__warp_se_78) = WS3_INDEX_felt_to_warp_id(
                    __warp_usrid13_rightsOver, __warp_se_77
                );

                let (__warp_se_79) = WS0_READ_warp_id(__warp_se_78);

                let (__warp_se_80) = WARP_DARRAY1_Uint256_IDX(__warp_se_79, __warp_usrid45_i);

                let (__warp_se_81) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_82) = WS0_READ_warp_id(__warp_se_81);

                let (__warp_se_83) = WARP_DARRAY0_felt_IDX(__warp_se_82, __warp_usrid41_j);

                let (__warp_se_84) = WS2_READ_felt(__warp_se_83);

                let (__warp_se_85) = WS3_INDEX_felt_to_warp_id(
                    __warp_usrid13_rightsOver, __warp_se_84
                );

                let (__warp_se_86) = WS0_READ_warp_id(__warp_se_85);

                let (__warp_se_87) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_88) = WS0_READ_warp_id(__warp_se_87);

                let (__warp_se_89) = WARP_DARRAY0_felt_IDX(__warp_se_88, __warp_usrid41_j);

                let (__warp_se_90) = WS2_READ_felt(__warp_se_89);

                let (__warp_se_91) = WS3_INDEX_felt_to_warp_id(
                    __warp_usrid13_rightsOver, __warp_se_90
                );

                let (__warp_se_92) = WS0_READ_warp_id(__warp_se_91);

                let (__warp_se_93) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_92);

                let (__warp_se_94) = warp_sub256(__warp_se_93, Uint256(low=1, high=0));

                let (__warp_se_95) = WARP_DARRAY1_Uint256_IDX(__warp_se_86, __warp_se_94);

                let (__warp_se_96) = WS1_READ_Uint256(__warp_se_95);

                WS_WRITE0(__warp_se_80, __warp_se_96);

                let (__warp_se_97) = WS0_INDEX_Uint256_to_warp_id(
                    __warp_usrid17_rightHolders, __warp_usrid39__rightid
                );

                let (__warp_se_98) = WS0_READ_warp_id(__warp_se_97);

                let (__warp_se_99) = WARP_DARRAY0_felt_IDX(__warp_se_98, __warp_usrid41_j);

                let (__warp_se_100) = WS2_READ_felt(__warp_se_99);

                let (__warp_se_101) = WS3_INDEX_felt_to_warp_id(
                    __warp_usrid13_rightsOver, __warp_se_100
                );

                let (__warp_se_102) = WS0_READ_warp_id(__warp_se_101);

                WARP_DARRAY1_Uint256_POP(__warp_se_102);

                let __warp_usrid45_i = __warp_usrid45_i;

                let __warp_usrid39__rightid = __warp_usrid39__rightid;

                let __warp_usrid41_j = __warp_usrid41_j;

                return (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j);
            }else{
                let (
                    __warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j
                ) = __warp_while0_if(_part2(
                    __warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j
                ));

                return (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j);
            }
        }else{
            let __warp_usrid45_i = __warp_usrid45_i;

            let __warp_usrid39__rightid = __warp_usrid39__rightid;

            let __warp_usrid41_j = __warp_usrid41_j;

            return (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j);
        }
    }

    func __warp_while0_if_part2{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ) -> (
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ){
        alloc_locals;

        let (__warp_se_103) = warp_add256(__warp_usrid45_i, Uint256(low=1, high=0));

        let __warp_se_104 = __warp_se_103;

        let __warp_usrid45_i = __warp_se_104;

        warp_sub256(__warp_se_104, Uint256(low=1, high=0));

        let (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j) = __warp_while0_if(_part1(
            __warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j
        ));

        return (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j);
    }

    func __warp_while0_if_part1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ) -> (
        __warp_usrid45_i : Uint256, __warp_usrid39__rightid : Uint256, __warp_usrid41_j : Uint256
    ){
        alloc_locals;

        let (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j) = __warp_while0(
            __warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j
        );

        return (__warp_usrid45_i, __warp_usrid39__rightid, __warp_usrid41_j);
    }

    func __warp_isNFTOwner_8{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid28__rightid : Uint256,
        __warp_parameter5 : Uint256,
        __warp_parameter6 : felt,
        __warp_parameter7 : Uint256,
    ) -> (){
        alloc_locals;

        let (__warp_se_105) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid28__rightid
        );

        let (__warp_se_106) = WS2_READ_felt(__warp_se_105);

        let (__warp_se_107) = get_caller_address();

        let (__warp_se_108) = warp_eq(__warp_se_106, __warp_se_107);

        with_attr error_message("only the NFT Owner"){
            assert __warp_se_108 = 1;
        }

        __warp_original_function_setAvailability_e0beb8c0(
            __warp_parameter5, __warp_parameter6, __warp_parameter7
        );

        return ();
    }

    func __warp_original_function_setAvailability_e0beb8c0{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid51__rightid : Uint256,
        __warp_usrid52__available : felt,
        __warp_usrid53__nftindex : Uint256,
    ) -> (){
        alloc_locals;

        let (__warp_se_109) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid51__rightid
        );

        let (__warp_se_110) = WS2_READ_felt(__warp_se_109);

        let (__warp_se_111) = warp_eq(__warp_se_110, 1);

        if( __warp_se_111 != 0){
            let (__warp_se_112) = WARP_DARRAY1_Uint256_IDX(
                __warp_usrid4_availableRights, __warp_usrid53__nftindex
            );

            let (__warp_se_113) = WS1_READ_Uint256(__warp_se_112);

            let (__warp_se_114) = warp_eq256(__warp_se_113, __warp_usrid51__rightid);

            with_attr error_message("wrong index for rightid"){
                assert __warp_se_114 = 1;
            }

            __warp_original_function_setAvailability_e0beb8c0_if(_part1(
                __warp_usrid52__available, __warp_usrid53__nftindex, __warp_usrid51__rightid
            ));

            return ();
        }else{
            __warp_original_function_setAvailability_e0beb8c0_if(_part1(
                __warp_usrid52__available, __warp_usrid53__nftindex, __warp_usrid51__rightid
            ));

            return ();
        }
    }

    func __warp_original_function_setAvailability_e0beb8c0_if_part1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid52__available : felt,
        __warp_usrid53__nftindex : Uint256,
        __warp_usrid51__rightid : Uint256,
    ) -> (){
        alloc_locals;

        let (__warp_se_115) = warp_eq(__warp_usrid52__available, 0);

        if( __warp_se_115 != 0){
            let (__warp_se_116) = WARP_DARRAY1_Uint256_IDX(
                __warp_usrid4_availableRights, __warp_usrid53__nftindex
            );

            let (__warp_se_117) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_usrid4_availableRights);

            let (__warp_se_118) = warp_sub256(__warp_se_117, Uint256(low=1, high=0));

            let (__warp_se_119) = WARP_DARRAY1_Uint256_IDX(
                __warp_usrid4_availableRights, __warp_se_118
            );

            let (__warp_se_120) = WS1_READ_Uint256(__warp_se_119);

            WS_WRITE0(__warp_se_116, __warp_se_120);

            WARP_DARRAY1_Uint256_POP(__warp_usrid4_availableRights);

            __warp_original_function_setAvailability_e0beb8c0_if(_part1_if(_part1(
                __warp_usrid51__rightid, __warp_usrid52__available
            )));

            return ();
        }else{
            WARP_DARRAY1_Uint256_PUSHV0(__warp_usrid4_availableRights, __warp_usrid51__rightid);

            __warp_original_function_setAvailability_e0beb8c0_if(_part1_if(_part1(
                __warp_usrid51__rightid, __warp_usrid52__available
            )));

            return ();
        }
    }

    func __warp_original_function_setAvailability_e0beb8c0_if_part1_if_part1{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid51__rightid : Uint256, __warp_usrid52__available : felt) -> (){
        alloc_locals;

        let (__warp_se_121) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid51__rightid
        );

        WS_WRITE1(__warp_se_121, __warp_usrid52__available);

        return ();
    }

    func __warp_isNFTOwner_4{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
        warp_memory : DictAccess*,
    }(
        __warp_usrid28__rightid : Uint256, __warp_parameter2 : Uint256, __warp_parameter3 : Uint256
    ) -> (){
        alloc_locals;

        let (__warp_se_122) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid28__rightid
        );

        let (__warp_se_123) = WS2_READ_felt(__warp_se_122);

        let (__warp_se_124) = get_caller_address();

        let (__warp_se_125) = warp_eq(__warp_se_123, __warp_se_124);

        with_attr error_message("only the NFT Owner"){
            assert __warp_se_125 = 1;
        }

        __warp_original_function_withdrawNFT_3a0196af(__warp_parameter2, __warp_parameter3);

        return ();
    }

    func __warp_original_function_withdrawNFT_3a0196af{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
        warp_memory : DictAccess*,
    }(__warp_usrid46__rightid : Uint256, __warp_usrid47__rightIndex : Uint256) -> (){
        alloc_locals;

        let (__warp_se_126) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid5_highestDeadline, __warp_usrid46__rightid
        );

        let (__warp_se_127) = WS1_READ_Uint256(__warp_se_126);

        let (__warp_se_128) = warp_block_timestamp();

        let (__warp_se_129) = warp_lt256(__warp_se_127, __warp_se_128);

        with_attr error_message("highest right deadline should } before withdraw"){
            assert __warp_se_129 = 1;
        }

        let (__warp_se_130) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid46__rightid
        );

        let (__warp_se_131) = WS2_READ_felt(__warp_se_130);

        let (__warp_se_132) = warp_eq(__warp_se_131, 0);

        with_attr error_message("NFT should be unavailable"){
            assert __warp_se_132 = 1;
        }

        let (__warp_se_133) = get_caller_address();

        let (__warp_se_134) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_133);

        let (__warp_se_135) = WS0_READ_warp_id(__warp_se_134);

        let (__warp_se_136) = WARP_DARRAY1_Uint256_IDX(__warp_se_135, __warp_usrid47__rightIndex);

        let (__warp_se_137) = WS1_READ_Uint256(__warp_se_136);

        let (__warp_se_138) = warp_eq256(__warp_se_137, __warp_usrid46__rightid);

        with_attr error_message("wrong index for collection address"){
            assert __warp_se_138 = 1;
        }

        let (__warp_se_139) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid46__rightid
        );

        let (__warp_se_140) = WS0_READ_warp_id(__warp_se_139);

        let (__warp_se_141) = WARP_DARRAY1_Uint256_IDX(__warp_se_140, Uint256(low=0, high=0));

        let (__warp_se_142) = WS1_READ_Uint256(__warp_se_141);

        let (__warp_usrid48_erc721) = uint256_to_address_felt(__warp_se_142);

        let (__warp_se_143) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid46__rightid
        );

        let (__warp_se_144) = WS0_READ_warp_id(__warp_se_143);

        let (__warp_se_145) = WARP_DARRAY1_Uint256_IDX(__warp_se_144, Uint256(low=1, high=0));

        let (__warp_usrid49_nftid) = WS1_READ_Uint256(__warp_se_145);

        __warp_usrfn1__burn(__warp_usrid46__rightid, __warp_usrid47__rightIndex);

        let (__warp_se_146) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid5_highestDeadline, __warp_usrid46__rightid
        );

        WS_WRITE0(__warp_se_146, Uint256(low=0, high=0));

        let __warp_usrid50_e721 = __warp_usrid48_erc721;

        let (__warp_se_147) = get_contract_address();

        let (__warp_se_148) = get_caller_address();

        IERC721_warped_interface.transferFrom_23b872dd(
            __warp_usrid50_e721, __warp_se_147, __warp_se_148, __warp_usrid49_nftid
        );

        return ();
    }

    func __warp_isNFTOwner_1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid28__rightid : Uint256, __warp_parameter0 : Uint256) -> (){
        alloc_locals;

        let (__warp_se_149) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid28__rightid
        );

        let (__warp_se_150) = WS2_READ_felt(__warp_se_149);

        let (__warp_se_151) = get_caller_address();

        let (__warp_se_152) = warp_eq(__warp_se_150, __warp_se_151);

        with_attr error_message("only the NFT Owner"):
            assert __warp_se_152 = 1
        }

        __warp_original_function_withdrawRoyalties_5daa02ed(__warp_parameter0);

        return ();
    }

    func __warp_original_function_withdrawRoyalties_5daa02ed{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid39__rightid : Uint256) -> ():
        alloc_locals;

        let (__warp_se_153) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid17_rightHolders, __warp_usrid39__rightid
        );

        let (__warp_se_154) = WS0_READ_warp_id(__warp_se_153);

        let (__warp_se_155) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_154);

        let (__warp_se_156) = warp_gt256(__warp_se_155, Uint256(low=0, high=0));

        with_attr error_message("right does not exists"):
            assert __warp_se_156 = 1
        }

        let __warp_usrid40_amountToWithdraw = Uint256(low=0, high=0);

        let __warp_usrid41_j = Uint256(low=0, high=0);

        let (__warp_tv_3, __warp_tv_4, __warp_tv_5) = __warp_while1(
            __warp_usrid39__rightid, __warp_usrid41_j, __warp_usrid40_amountToWithdraw
        );

        let __warp_usrid40_amountToWithdraw = __warp_tv_5

        let __warp_usrid41_j = __warp_tv_4

        let __warp_usrid39__rightid = __warp_tv_3

        let (__warp_se_157) = get_caller_address();

        RoyaltiesWithdraw_644800e6.emit(__warp_se_157, __warp_usrid40_amountToWithdraw);

        return ();
    }

    @external
    func getRights_1d3ae1b2{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid29__rightid : Uint256, __warp_usrid30__period : Uint256) -> ():
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid30__period);

        warp_external_input_check_int256(__warp_usrid29__rightid);

        let (__warp_se_158) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid29__rightid
        );

        let (__warp_se_159) = WS2_READ_felt(__warp_se_158);

        with_attr error_message("NFT is not available"):
            assert __warp_se_159 = 1
        }

        let (__warp_se_160) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid12_maxtime, __warp_usrid29__rightid
        );

        let (__warp_se_161) = WS1_READ_Uint256(__warp_se_160);

        let (__warp_se_162) = warp_ge256(__warp_se_161, __warp_usrid30__period);

        with_attr error_message("period is above the max period"):
            assert __warp_se_162 = 1
        }

        let (__warp_se_163) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid29__rightid
        );

        let (__warp_se_164) = WS1_READ_Uint256(__warp_se_163);

        let (__warp_se_165) = warp_gt256(__warp_se_164, Uint256(low=0, high=0));

        with_attr error_message("limit of right holders reached"):
            assert __warp_se_165 = 1
        }

        let (__warp_se_166) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid19_rightsPeriod, __warp_usrid29__rightid
        );

        let (__warp_se_167) = WS0_READ_warp_id(__warp_se_166);

        let (__warp_se_168) = get_caller_address();

        let (__warp_se_169) = WS1_INDEX_felt_to_Uint256(__warp_se_167, __warp_se_168);

        let (__warp_se_170) = WS1_READ_Uint256(__warp_se_169);

        let (__warp_se_171) = warp_eq256(__warp_se_170, Uint256(low=0, high=0));

        with_attr error_message("already buy this right"):
            assert __warp_se_171 = 1
        }

        let (__warp_se_172) = warp_gt256(__warp_usrid30__period, Uint256(low=0, high=0));

        with_attr error_message("period is equal to 0"):
            assert __warp_se_172 = 1
        }

        let (__warp_se_173) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid29__rightid
        );

        let (__warp_se_174) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid29__rightid
        );

        let (__warp_se_175) = WS1_READ_Uint256(__warp_se_174);

        let (__warp_se_176) = warp_sub256(__warp_se_175, Uint256(low=1, high=0));

        WS_WRITE0(__warp_se_173, __warp_se_176);

        let (__warp_se_177) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid19_rightsPeriod, __warp_usrid29__rightid
        );

        let (__warp_se_178) = WS0_READ_warp_id(__warp_se_177);

        let (__warp_se_179) = get_caller_address();

        let (__warp_se_180) = WS1_INDEX_felt_to_Uint256(__warp_se_178, __warp_se_179);

        WS_WRITE0(__warp_se_180, __warp_usrid30__period);

        let (__warp_se_181) = get_caller_address();

        let (__warp_se_182) = WS3_INDEX_felt_to_warp_id(__warp_usrid13_rightsOver, __warp_se_181);

        let (__warp_se_183) = WS0_READ_warp_id(__warp_se_182);

        WARP_DARRAY1_Uint256_PUSHV0(__warp_se_183, __warp_usrid29__rightid);

        let (__warp_se_184) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid18_deadline, __warp_usrid29__rightid
        );

        let (__warp_se_185) = WS0_READ_warp_id(__warp_se_184);

        let (__warp_se_186) = get_caller_address();

        let (__warp_se_187) = WS1_INDEX_felt_to_Uint256(__warp_se_185, __warp_se_186);

        let (__warp_se_188) = warp_block_timestamp();

        let (__warp_se_189) = warp_mul256(Uint256(low=86400, high=0), __warp_usrid30__period);

        let (__warp_se_190) = warp_add256(__warp_se_188, __warp_se_189);

        WS_WRITE0(__warp_se_187, __warp_se_190);

        let (__warp_se_191) = warp_block_timestamp();

        let (__warp_se_192) = warp_mul256(Uint256(low=86400, high=0), __warp_usrid30__period);

        let (__warp_se_193) = warp_add256(__warp_se_191, __warp_se_192);

        let (__warp_se_194) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid5_highestDeadline, __warp_usrid29__rightid
        );

        let (__warp_se_195) = WS1_READ_Uint256(__warp_se_194);

        let (__warp_se_196) = warp_gt256(__warp_se_193, __warp_se_195);

        if( __warp_se_196 != 0:
            let (__warp_se_197) = WS2_INDEX_Uint256_to_Uint256(
                __warp_usrid5_highestDeadline, __warp_usrid29__rightid
            );

            let (__warp_se_198) = warp_block_timestamp();

            let (__warp_se_199) = warp_mul256(Uint256(low=86400, high=0), __warp_usrid30__period);

            let (__warp_se_200) = warp_add256(__warp_se_198, __warp_se_199);

            WS_WRITE0(__warp_se_197, __warp_se_200);

            getRights_1d3ae1b2_if(_part1(__warp_usrid29__rightid, __warp_usrid30__period);

            return ();
        }else{
            getRights_1d3ae1b2_if(_part1(__warp_usrid29__rightid, __warp_usrid30__period);

            return ();
        }
    }

    func getRights_1d3ae1b2_if(_part1{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid29__rightid : Uint256, __warp_usrid30__period : Uint256) -> ():
        alloc_locals;

        let (__warp_se_201) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid17_rightHolders, __warp_usrid29__rightid
        );

        let (__warp_se_202) = WS0_READ_warp_id(__warp_se_201);

        let (__warp_se_203) = get_caller_address();

        WARP_DARRAY0_felt_PUSHV1(__warp_se_202, __warp_se_203);

        let (__warp_se_204) = get_caller_address();

        GetRight_4215fdfe.emit(__warp_usrid29__rightid, __warp_usrid30__period, __warp_se_204);

        return ();
    }

    @external
    func depositNFT_d21d34f4{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid31__erc721 : felt,
        __warp_usrid32__nftid : Uint256,
        __warp_usrid33__dailyPrice : Uint256,
        __warp_usrid34__maxPeriod : Uint256,
        __warp_usrid35__amount : Uint256,
    ) -> ():
        alloc_locals;
        let (local keccak_ptr_start : felt*) = alloc();
        let keccak_ptr = keccak_ptr_start
        let (local warp_memory : DictAccess*) = default_dict_new(0);
        local warp_memory_start : DictAccess* = warp_memory
        dict_write{dict_ptr=warp_memory}(0, 1);
        with warp_memory, keccak_ptr:
            warp_external_input_check_int256(__warp_usrid35__amount);

            warp_external_input_check_int256(__warp_usrid34__maxPeriod);

            warp_external_input_check_int256(__warp_usrid33__dailyPrice);

            warp_external_input_check_int256(__warp_usrid32__nftid);

            warp_external_input_check_address(__warp_usrid31__erc721);

            let (__warp_se_205) = warp_neq(__warp_usrid31__erc721, 0);

            with_attr error_message("collection address is zero"):
                assert __warp_se_205 = 1
            }

            let __warp_usrid36_e721metadata = __warp_usrid31__erc721

            let (
                __warp_usrid37_uri_cd_raw_len, __warp_usrid37_uri_cd_raw
            ) = ERC721Metadata_warped_interface.tokenURI_c87b56dd(
                __warp_usrid36_e721metadata, __warp_usrid32__nftid
            );

            local __warp_usrid37_uri_cd : cd_dynarray_felt = cd_dynarray_felt(__warp_usrid37_uri_cd_raw_len, __warp_usrid37_uri_cd_raw);

            let (__warp_usrid37_uri) = cd_to_memory0(__warp_usrid37_uri_cd);

            __warp_usrfn0__mint(
                __warp_usrid31__erc721,
                __warp_usrid32__nftid,
                __warp_usrid35__amount,
                __warp_usrid33__dailyPrice,
                __warp_usrid34__maxPeriod,
                __warp_usrid37_uri,
            );

            let __warp_usrid38_e721 = __warp_usrid31__erc721

            let (__warp_se_206) = get_caller_address();

            let (__warp_se_207) = get_contract_address();

            IERC721_warped_interface.transferFrom_23b872dd(
                __warp_usrid38_e721, __warp_se_206, __warp_se_207, __warp_usrid32__nftid
            );

            DepositedNFT_8b187cf9.emit(__warp_usrid31__erc721, __warp_usrid32__nftid);

            default_dict_finalize(warp_memory_start, warp_memory, 0);

            finalize_keccak(keccak_ptr_start, keccak_ptr);

            return ();
        }
    }

    @external
    func withdrawRoyalties_5daa02ed{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid39__rightid : Uint256) -> ():
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid39__rightid);

        __warp_isNFTOwner_1(__warp_usrid39__rightid, __warp_usrid39__rightid);

        return ();
    }

    @external
    func withdrawNFT_3a0196af{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(__warp_usrid46__rightid : Uint256, __warp_usrid47__rightIndex : Uint256) -> ():
        alloc_locals;
        let (local warp_memory : DictAccess*) = default_dict_new(0);
        local warp_memory_start : DictAccess* = warp_memory
        dict_write{dict_ptr=warp_memory}(0, 1);
        with warp_memory:
            warp_external_input_check_int256(__warp_usrid47__rightIndex);

            warp_external_input_check_int256(__warp_usrid46__rightid);

            __warp_isNFTOwner_4(
                __warp_usrid46__rightid, __warp_usrid46__rightid, __warp_usrid47__rightIndex
            );

            default_dict_finalize(warp_memory_start, warp_memory, 0);

            return ();
        }
    }

    @external
    func setAvailability_e0beb8c0{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
    }(
        __warp_usrid51__rightid : Uint256,
        __warp_usrid52__available : felt,
        __warp_usrid53__nftindex : Uint256,
    ) -> ():
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid53__nftindex);

        warp_external_input_check_bool(__warp_usrid52__available);

        warp_external_input_check_int256(__warp_usrid51__rightid);

        __warp_isNFTOwner_8(
            __warp_usrid51__rightid,
            __warp_usrid51__rightid,
            __warp_usrid52__available,
            __warp_usrid53__nftindex,
        );

        return ();
    }

    @external
    func verif(yRight_088ce803{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid54__rightid : Uint256, __warp_usrid55__platform : felt) -> ():
        alloc_locals;

        warp_external_input_check_address(__warp_usrid55__platform);

        warp_external_input_check_int256(__warp_usrid54__rightid);

        let (__warp_se_208) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid19_rightsPeriod, __warp_usrid54__rightid
        );

        let (__warp_se_209) = WS0_READ_warp_id(__warp_se_208);

        let (__warp_se_210) = WS1_INDEX_felt_to_Uint256(__warp_se_209, __warp_usrid55__platform);

        let (__warp_se_211) = WS1_READ_Uint256(__warp_se_210);

        let (__warp_se_212) = warp_eq256(__warp_se_211, Uint256(low=0, high=0));

        with_attr error_message("the platform cannot be the right holder"):
            assert __warp_se_212 = 1
        }

        let (__warp_se_213) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid19_rightsPeriod, __warp_usrid54__rightid
        );

        let (__warp_se_214) = WS0_READ_warp_id(__warp_se_213);

        let (__warp_se_215) = get_caller_address();

        let (__warp_se_216) = WS1_INDEX_felt_to_Uint256(__warp_se_214, __warp_se_215);

        let (__warp_se_217) = WS1_READ_Uint256(__warp_se_216);

        let (__warp_se_218) = warp_gt256(__warp_se_217, Uint256(low=0, high=0));

        with_attr error_message("s}er is not the right holder"):
            assert __warp_se_218 = 1
        }

        let (__warp_se_219) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid18_deadline, __warp_usrid54__rightid
        );

        let (__warp_se_220) = WS0_READ_warp_id(__warp_se_219);

        let (__warp_se_221) = get_caller_address();

        let (__warp_se_222) = WS1_INDEX_felt_to_Uint256(__warp_se_220, __warp_se_221);

        let (__warp_se_223) = WS1_READ_Uint256(__warp_se_222);

        let (__warp_se_224) = warp_block_timestamp();

        let (__warp_se_225) = warp_gt256(__warp_se_223, __warp_se_224);

        with_attr error_message("has exceeded the right time"):
            assert __warp_se_225 = 1
        }

        let (__warp_se_226) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid20_validated, __warp_usrid54__rightid
        );

        let (__warp_se_227) = WS0_READ_warp_id(__warp_se_226);

        let (__warp_se_228) = WS3_INDEX_felt_to_warp_id(__warp_se_227, __warp_usrid55__platform);

        let (__warp_se_229) = WS0_READ_warp_id(__warp_se_228);

        let (__warp_se_230) = get_caller_address();

        let (__warp_se_231) = WS5_INDEX_felt_to_felt(__warp_se_229, __warp_se_230);

        let (__warp_se_232) = WS2_READ_felt(__warp_se_231);

        let (__warp_se_233) = warp_eq(__warp_se_232, 0);

        with_attr error_message("rightid and right holder are already validated"):
            assert __warp_se_233 = 1
        }

        let (__warp_se_234) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid20_validated, __warp_usrid54__rightid
        );

        let (__warp_se_235) = WS0_READ_warp_id(__warp_se_234);

        let (__warp_se_236) = WS3_INDEX_felt_to_warp_id(__warp_se_235, __warp_usrid55__platform);

        let (__warp_se_237) = WS0_READ_warp_id(__warp_se_236);

        let (__warp_se_238) = get_caller_address();

        let (__warp_se_239) = WS5_INDEX_felt_to_felt(__warp_se_237, __warp_se_238);

        WS_WRITE1(__warp_se_239, 1);

        let (__warp_usrid56_ct) = WS2_READ_felt(__warp_usrid2_governanceToken);

        let (__warp_se_240) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid10_dailyPrice, __warp_usrid54__rightid
        );

        let (__warp_se_241) = WS1_READ_Uint256(__warp_se_240);

        let (__warp_se_242) = warp_div256(__warp_se_241, Uint256(low=2, high=0));

        Token_warped_interface.mint_40c10f19(
            __warp_usrid56_ct, __warp_usrid55__platform, __warp_se_242
        );

        return ();
    }

    @view
    func verif(ied_24d73567{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid57__rightid : Uint256, __warp_usrid58__platform : felt) -> (
        __warp_usrid59_ : felt
    ):
        alloc_locals;

        warp_external_input_check_address(__warp_usrid58__platform);

        warp_external_input_check_int256(__warp_usrid57__rightid);

        let (__warp_se_243) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid20_validated, __warp_usrid57__rightid
        );

        let (__warp_se_244) = WS0_READ_warp_id(__warp_se_243);

        let (__warp_se_245) = WS3_INDEX_felt_to_warp_id(__warp_se_244, __warp_usrid58__platform);

        let (__warp_se_246) = WS0_READ_warp_id(__warp_se_245);

        let (__warp_se_247) = get_caller_address();

        let (__warp_se_248) = WS5_INDEX_felt_to_felt(__warp_se_246, __warp_se_247);

        let (__warp_se_249) = WS2_READ_felt(__warp_se_248);

        return (__warp_se_249);
    }

    func __warp_usrfn0__mint{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
        warp_memory : DictAccess*,
        keccak_ptr : felt*,
    }(
        __warp_usrid60__erc721 : felt,
        __warp_usrid61__nftid : Uint256,
        __warp_usrid62__amount : Uint256,
        __warp_usrid63__dailyPrice : Uint256,
        __warp_usrid64__maxPeriod : Uint256,
        __warp_usrid65__nftUri : felt,
    ) -> ():
        alloc_locals;

        let (__warp_se_250) = abi_encode0(__warp_usrid60__erc721, __warp_usrid61__nftid);

        let (__warp_usrid66_rightid) = warp_keccak(__warp_se_250);

        let (__warp_se_251) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid66_rightid
        );

        WS_WRITE0(__warp_se_251, __warp_usrid62__amount);

        let (__warp_se_252) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid10_dailyPrice, __warp_usrid66_rightid
        );

        WS_WRITE0(__warp_se_252, __warp_usrid63__dailyPrice);

        let (__warp_se_253) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid12_maxtime, __warp_usrid66_rightid
        );

        WS_WRITE0(__warp_se_253, __warp_usrid64__maxPeriod);

        let (__warp_se_254) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid66_rightid
        );

        let (__warp_se_255) = get_caller_address();

        WS_WRITE1(__warp_se_254, __warp_se_255);

        let (__warp_se_256) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid66_rightid
        );

        let (__warp_se_257) = WS0_READ_warp_id(__warp_se_256);

        let (__warp_se_258) = felt_to_uint256(__warp_usrid60__erc721);

        WARP_DARRAY1_Uint256_PUSHV2(__warp_se_257, __warp_se_258);

        let (__warp_se_259) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid66_rightid
        );

        let (__warp_se_260) = WS0_READ_warp_id(__warp_se_259);

        WARP_DARRAY1_Uint256_PUSHV2(__warp_se_260, __warp_usrid61__nftid);

        let (__warp_se_261) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid9_rightUri, __warp_usrid66_rightid
        );

        let (__warp_se_262) = WS0_READ_warp_id(__warp_se_261);

        wm_to_storage0(__warp_se_262, __warp_usrid65__nftUri);

        let (__warp_se_263) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid66_rightid
        );

        WS_WRITE1(__warp_se_263, 1);

        let (__warp_se_264) = get_caller_address();

        let (__warp_se_265) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_264);

        let (__warp_se_266) = WS0_READ_warp_id(__warp_se_265);

        WARP_DARRAY1_Uint256_PUSHV0(__warp_se_266, __warp_usrid66_rightid);

        WARP_DARRAY1_Uint256_PUSHV0(__warp_usrid4_availableRights, __warp_usrid66_rightid);

        return ();
    }

    func __warp_usrfn1__burn{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr : felt,
        bitwise_ptr : BitwiseBuiltin*,
        warp_memory : DictAccess*,
    }(__warp_usrid67__rightid : Uint256, __warp_usrid68__rightIndex : Uint256) -> ():
        alloc_locals;

        let (__warp_se_267) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid67__rightid
        );

        WS_WRITE0(__warp_se_267, Uint256(low=0, high=0));

        let (__warp_se_268) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid10_dailyPrice, __warp_usrid67__rightid
        );

        WS_WRITE0(__warp_se_268, Uint256(low=0, high=0));

        let (__warp_se_269) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid12_maxtime, __warp_usrid67__rightid
        );

        WS_WRITE0(__warp_se_269, Uint256(low=0, high=0));

        let (__warp_se_270) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid67__rightid
        );

        let (__warp_se_271) = WS0_READ_warp_id(__warp_se_270);

        WARP_DARRAY1_Uint256_POP(__warp_se_271);

        let (__warp_se_272) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid67__rightid
        );

        let (__warp_se_273) = WS0_READ_warp_id(__warp_se_272);

        WARP_DARRAY1_Uint256_POP(__warp_se_273);

        let (__warp_se_274) = get_caller_address();

        let (__warp_se_275) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_274);

        let (__warp_se_276) = WS0_READ_warp_id(__warp_se_275);

        let (__warp_se_277) = WARP_DARRAY1_Uint256_IDX(__warp_se_276, __warp_usrid68__rightIndex);

        let (__warp_se_278) = get_caller_address();

        let (__warp_se_279) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_278);

        let (__warp_se_280) = WS0_READ_warp_id(__warp_se_279);

        let (__warp_se_281) = get_caller_address();

        let (__warp_se_282) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_281);

        let (__warp_se_283) = WS0_READ_warp_id(__warp_se_282);

        let (__warp_se_284) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_283);

        let (__warp_se_285) = warp_sub256(__warp_se_284, Uint256(low=1, high=0));

        let (__warp_se_286) = WARP_DARRAY1_Uint256_IDX(__warp_se_280, __warp_se_285);

        let (__warp_se_287) = WS1_READ_Uint256(__warp_se_286);

        WS_WRITE0(__warp_se_277, __warp_se_287);

        let (__warp_se_288) = get_caller_address();

        let (__warp_se_289) = WS3_INDEX_felt_to_warp_id(__warp_usrid14_properties, __warp_se_288);

        let (__warp_se_290) = WS0_READ_warp_id(__warp_se_289);

        WARP_DARRAY1_Uint256_POP(__warp_se_290);

        let (__warp_se_291) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid9_rightUri, __warp_usrid67__rightid
        );

        let (__warp_se_292) = WS0_READ_warp_id(__warp_se_291);

        let (__warp_se_293) = WM0_d_arr();

        wm_to_storage0(__warp_se_292, __warp_se_293);

        let (__warp_se_294) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid67__rightid
        );

        WS_WRITE1(__warp_se_294, 0);

        return ();
    }

    @external
    func setGovernanceToken_f8570170{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid69__newToken : felt) -> ():
        alloc_locals;

        warp_external_input_check_address(__warp_usrid69__newToken);

        let (__warp_se_295) = WS2_READ_felt(__warp_usrid3_contractOwner);

        let (__warp_se_296) = get_caller_address();

        let (__warp_se_297) = warp_eq(__warp_se_295, __warp_se_296);

        assert __warp_se_297 = 1

        WS_WRITE1(__warp_usrid2_governanceToken, __warp_usrid69__newToken);

        return ();
    }

    @view
    func currentTreasury_0f265bdd{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }() -> (__warp_usrid70_ : Uint256):
        alloc_locals;

        let (__warp_se_298) = WS1_READ_Uint256(__warp_usrid0_treasury);

        return (__warp_se_298);
    }

    @view
    func dailyPriceOf_ba987777{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid71__rightid : Uint256) -> (__warp_usrid72_ : Uint256):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid71__rightid);

        let (__warp_se_299) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid10_dailyPrice, __warp_usrid71__rightid
        );

        let (__warp_se_300) = WS1_READ_Uint256(__warp_se_299);

        return (__warp_se_300);
    }

    @view
    func availableRightsOf_4394dd76{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid73__rightid : Uint256) -> (__warp_usrid74_ : Uint256):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid73__rightid);

        let (__warp_se_301) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid11_maxRightsHolders, __warp_usrid73__rightid
        );

        let (__warp_se_302) = WS1_READ_Uint256(__warp_se_301);

        return (__warp_se_302);
    }

    @view
    func maxPeriodOf_26e07ef6{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid75__rightid : Uint256) -> (__warp_usrid76_ : Uint256):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid75__rightid);

        let (__warp_se_303) = WS2_INDEX_Uint256_to_Uint256(
            __warp_usrid12_maxtime, __warp_usrid75__rightid
        );

        let (__warp_se_304) = WS1_READ_Uint256(__warp_se_303);

        return (__warp_se_304);
    }

    @view
    func rightsPeriodOf_ef3776d7{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid77__rightid : Uint256, __warp_usrid78__holder : felt) -> (
        __warp_usrid79_ : Uint256
    ):
        alloc_locals;

        warp_external_input_check_address(__warp_usrid78__holder);

        warp_external_input_check_int256(__warp_usrid77__rightid);

        let (__warp_se_305) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid19_rightsPeriod, __warp_usrid77__rightid
        );

        let (__warp_se_306) = WS0_READ_warp_id(__warp_se_305);

        let (__warp_se_307) = WS1_INDEX_felt_to_Uint256(__warp_se_306, __warp_usrid78__holder);

        let (__warp_se_308) = WS1_READ_Uint256(__warp_se_307);

        return (__warp_se_308);
    }

    @view
    func rightsOf_9a9a4f46{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid80__rightsHolder : felt) -> (
        __warp_usrid81__len : felt, __warp_usrid81_ : Uint256*
    ):
        alloc_locals;

        warp_external_input_check_address(__warp_usrid80__rightsHolder);

        let (__warp_se_309) = WS3_INDEX_felt_to_warp_id(
            __warp_usrid13_rightsOver, __warp_usrid80__rightsHolder
        );

        let (__warp_se_310) = WS0_READ_warp_id(__warp_se_309);

        let (__warp_se_311) = ws_dynamic_array_to_calldata0(__warp_se_310);

        return (__warp_se_311.len, __warp_se_311.ptr);
    }

    @view
    func propertiesOf_c7c314e0{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid82__owner : felt) -> (__warp_usrid83__len : felt, __warp_usrid83_ : Uint256*):
        alloc_locals;

        warp_external_input_check_address(__warp_usrid82__owner);

        let (__warp_se_312) = WS3_INDEX_felt_to_warp_id(
            __warp_usrid14_properties, __warp_usrid82__owner
        );

        let (__warp_se_313) = WS0_READ_warp_id(__warp_se_312);

        let (__warp_se_314) = ws_dynamic_array_to_calldata0(__warp_se_313);

        return (__warp_se_314.len, __warp_se_314.ptr);
    }

    @view
    func getAvailableNFTs_32702c95{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }() -> (__warp_usrid84__len : felt, __warp_usrid84_ : Uint256*):
        alloc_locals;

        let (__warp_se_315) = ws_dynamic_array_to_calldata0(__warp_usrid4_availableRights);

        return (__warp_se_315.len, __warp_se_315.ptr);
    }

    @view
    func rightHoldersOf_e18138d7{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid85__rightid : Uint256) -> (__warp_usrid86__len : felt, __warp_usrid86_ : felt*):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid85__rightid);

        let (__warp_se_316) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid17_rightHolders, __warp_usrid85__rightid
        );

        let (__warp_se_317) = WS0_READ_warp_id(__warp_se_316);

        let (__warp_se_318) = ws_dynamic_array_to_calldata1(__warp_se_317);

        return (__warp_se_318.len, __warp_se_318.ptr);
    }

    @view
    func holderDeadline_5e4df22c{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid87__rightid : Uint256, __warp_usrid88__holder : felt) -> (
        __warp_usrid89_ : Uint256
    ):
        alloc_locals;

        warp_external_input_check_address(__warp_usrid88__holder);

        warp_external_input_check_int256(__warp_usrid87__rightid);

        let (__warp_se_319) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid18_deadline, __warp_usrid87__rightid
        );

        let (__warp_se_320) = WS0_READ_warp_id(__warp_se_319);

        let (__warp_se_321) = WS1_INDEX_felt_to_Uint256(__warp_se_320, __warp_usrid88__holder);

        let (__warp_se_322) = WS1_READ_Uint256(__warp_se_321);

        return (__warp_se_322);
    }

    @view
    func ownerOf_6352211e{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
        __warp_usrid90__rightid : Uint256
    ) -> (__warp_usrid91_ : felt):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid90__rightid);

        let (__warp_se_323) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid16_owner, __warp_usrid90__rightid
        );

        let (__warp_se_324) = WS2_READ_felt(__warp_se_323);

        return (__warp_se_324);
    }

    @view
    func availabilityOf_9fe8b786{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid92__rightid : Uint256) -> (__warp_usrid93_ : felt):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid92__rightid);

        let (__warp_se_325) = WS4_INDEX_Uint256_to_felt(
            __warp_usrid15_isAvailable, __warp_usrid92__rightid
        );

        let (__warp_se_326) = WS2_READ_felt(__warp_se_325);

        return (__warp_se_326);
    }

    @view
    func rightURI_e6be6db1{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid94__rightid : Uint256) -> (__warp_usrid95__len : felt, __warp_usrid95_ : felt*):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid94__rightid);

        let (__warp_se_327) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid9_rightUri, __warp_usrid94__rightid
        );

        let (__warp_se_328) = WS0_READ_warp_id(__warp_se_327);

        let (__warp_se_329) = ws_dynamic_array_to_calldata2(__warp_se_328);

        return (__warp_se_329.len, __warp_se_329.ptr);
    }

    @view
    func originOf_794b2a07{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt
    }(__warp_usrid96__rightid : Uint256) -> (
        __warp_usrid97__len : felt, __warp_usrid97_ : Uint256*
    ):
        alloc_locals;

        warp_external_input_check_int256(__warp_usrid96__rightid);

        let (__warp_se_330) = WS0_INDEX_Uint256_to_warp_id(
            __warp_usrid8_rightsOrigin, __warp_usrid96__rightid
        );

        let (__warp_se_331) = WS0_READ_warp_id(__warp_se_330);

        let (__warp_se_332) = ws_dynamic_array_to_calldata3(__warp_se_331);

        return (__warp_se_332.len, __warp_se_332.ptr);
    }

    @constructor
    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}():
        alloc_locals;
        WARP_USED_STORAGE.write(23);
        WARP_NAMEGEN.write(17);

        return ();
    }
}

// Contract Def ERC721Metadata@interface

@contract_interface
namespace ERC721Metadata_warped_interface:
    func tokenURI_c87b56dd(__warp_usrid0__tokenId : Uint256) -> (
        __warp_usrid1__len : felt, __warp_usrid1_ : felt*
    ):
    }

    func constructor():
    }
}

// Contract Def IERC721@interface

@contract_interface
namespace IERC721_warped_interface:
    func transferFrom_23b872dd(
        __warp_usrid0__from : felt, __warp_usrid1__to : felt, __warp_usrid2__tokenId : Uint256
    ) -> ():
    }

    func constructor():
    }
}

// Contract Def Token@interface

@contract_interface
namespace Token_warped_interface:
    func mint_40c10f19(__warp_usrid0__platform : felt, __warp_usrid1__amount : Uint256) -> ():
    }

    func burn_9dc29fac(__warp_usrid2__platform : felt, __warp_usrid3__amount : Uint256) -> ():
    }

    func constructor():
    }
}

// Original soldity abi: ["constructor();","getRights(uint256,uint256);","depositNFT(address,uint256,uint256,uint256,uint256);","withdrawRoyalties(uint256);","withdrawNFT(uint256,uint256);","setAvailability(uint256,bool,uint256);","verif(yRight(uint256,address);","verif(ied(uint256,address);","setGovernanceToken(address);","currentTreasury();","dailyPriceOf(uint256);","availableRightsOf(uint256);","maxPeriodOf(uint256);","rightsPeriodOf(uint256,address);","rightsOf(address);","propertiesOf(address);","getAvailableNFTs();","rightHoldersOf(uint256);","holderDeadline(uint256,address);","ownerOf(uint256);","availabilityOf(uint256);","rightURI(uint256);","originOf(uint256);"]
