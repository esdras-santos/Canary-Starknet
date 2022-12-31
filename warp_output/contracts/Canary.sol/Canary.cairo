%lang starknet


from warplib.memory import wm_alloc, wm_write_256, wm_dyn_array_length, wm_new, wm_to_felt_array
from starkware.cairo.common.uint256 import Uint256, uint256_sub, uint256_lt, uint256_eq, uint256_add
from starkware.cairo.common.dict import dict_write, dict_read
from warplib.maths.utils import narrow_safe, felt_to_uint256, uint256_to_address_felt
from warplib.maths.int_conversions import warp_uint256
from starkware.cairo.common.alloc import alloc
from warplib.maths.external_input_check_ints import warp_external_input_check_int256
from warplib.maths.external_input_check_address import warp_external_input_check_address
from warplib.maths.external_input_check_bool import warp_external_input_check_bool
from warplib.dynamic_arrays_util import fixed_bytes256_to_felt_dynamic_array, felt_array_to_warp_memory_array, fixed_bytes256_to_felt_dynamic_array_spl
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from warplib.keccak import felt_array_concat, pack_bytes_felt, warp_keccak
from starkware.starknet.common.syscalls import emit_event, get_caller_address, get_contract_address
from warplib.maths.gt import warp_gt256
from warplib.block_methods import warp_block_timestamp
from warplib.maths.lt import warp_lt256
from warplib.maths.mul import warp_mul256
from warplib.maths.div import warp_div256
from warplib.maths.sub import warp_sub256
from warplib.maths.add import warp_add256
from warplib.maths.eq import warp_eq256, warp_eq
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from warplib.maths.ge import warp_ge256
from warplib.maths.neq import warp_neq


struct cd_dynarray_felt{
     len : felt ,
     ptr : felt*,
}

struct cd_dynarray_Uint256{
     len : felt ,
     ptr : Uint256*,
}

func WM0_d_arr{range_check_ptr, warp_memory: DictAccess*}() -> (loc: felt){
    alloc_locals;
    let (start) = wm_alloc(Uint256(0x2, 0x0));
wm_write_256{warp_memory=warp_memory}(start, Uint256(0x0, 0x0));
    return (start,);
}

func wm_to_storage0_elem{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(storage_name: felt, mem_loc : felt, length: Uint256) -> (){
    alloc_locals;
    if (length.low == 0 and length.high == 0){
        return ();
    }
    let (index) = uint256_sub(length, Uint256(1,0));
    let (storage_loc) = WARP_DARRAY0_felt.read(storage_name, index);
    let mem_loc = mem_loc - 1;
    if (storage_loc == 0){
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
func wm_to_storage0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(loc : felt, mem_loc : felt) -> (loc : felt){
    alloc_locals;
    let (length) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (mem_length) = wm_dyn_array_length(mem_loc);
    WARP_DARRAY0_felt_LENGTH.write(loc, mem_length);
    let (narrowedLength) = narrow_safe(mem_length);
    wm_to_storage0_elem(loc, mem_loc + 2 + 1 * narrowedLength, mem_length);
    let (lesser) = uint256_lt(mem_length, length);
    if (lesser == 1){
       WS2_DYNAMIC_ARRAY_DELETE_elem(loc, mem_length, length);
       return (loc,);
    }else{
       return (loc,);
    }
}

func WS0_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt){
    WARP_STORAGE.write(loc, 0);
    return ();
}

func WS1_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt){
    WARP_STORAGE.write(loc, 0);
    WARP_STORAGE.write(loc + 1, 0);
    return ();
}

func WS2_DYNAMIC_ARRAY_DELETE_elem{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt, index : Uint256, length : Uint256){
     alloc_locals;
     let (stop) = uint256_eq(index, length);
     if (stop == 1){
        return ();
     }
     let (elem_loc) = WARP_DARRAY0_felt.read(loc, index);
    WS3_DELETE(elem_loc);
     let (next_index, _) = uint256_add(index, Uint256(0x1, 0x0));
     return WS2_DYNAMIC_ARRAY_DELETE_elem(loc, next_index, length);
}
func WS2_DYNAMIC_ARRAY_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt){
   alloc_locals;
   let (length) = WARP_DARRAY0_felt_LENGTH.read(loc);
   WARP_DARRAY0_felt_LENGTH.write(loc, Uint256(0x0, 0x0));
   return WS2_DYNAMIC_ARRAY_DELETE_elem(loc, Uint256(0x0, 0x0), length);
}

func WS3_DELETE{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt){
    WARP_STORAGE.write(loc, 0);
    return ();
}

func WARP_DARRAY0_felt_IDX{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(ref: felt, index: Uint256) -> (res: felt){
    alloc_locals;
    let (length) = WARP_DARRAY0_felt_LENGTH.read(ref);
    let (inRange) = uint256_lt(index, length);
    assert inRange = 1;
    let (existing) = WARP_DARRAY0_felt.read(ref, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_DARRAY0_felt.write(ref, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

func WARP_DARRAY1_Uint256_IDX{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(ref: felt, index: Uint256) -> (res: felt){
    alloc_locals;
    let (length) = WARP_DARRAY1_Uint256_LENGTH.read(ref);
    let (inRange) = uint256_lt(index, length);
    assert inRange = 1;
    let (existing) = WARP_DARRAY1_Uint256.read(ref, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(ref, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

func WARP_DARRAY0_felt_POP{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (isEmpty) = uint256_eq(len, Uint256(0,0));
    assert isEmpty = 0;
    let (newLen) = uint256_sub(len, Uint256(1,0));
    WARP_DARRAY0_felt_LENGTH.write(loc, newLen);
    let (elem_loc) = WARP_DARRAY0_felt.read(loc, newLen);
    return WS0_DELETE(elem_loc);
}

func WARP_DARRAY1_Uint256_POP{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (isEmpty) = uint256_eq(len, Uint256(0,0));
    assert isEmpty = 0;
    let (newLen) = uint256_sub(len, Uint256(1,0));
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, newLen);
    return WS1_DELETE(elem_loc);
}

func WARP_DARRAY1_Uint256_PUSHV0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr: BitwiseBuiltin*}(loc: felt, value: Uint256) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1,0));
    assert carry = 0;
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY1_Uint256.read(loc, len);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(loc, len, used);
WS_WRITE0(used, value);
    }else{
WS_WRITE0(existing, value);
    }
    return ();
}

func WARP_DARRAY0_felt_PUSHV1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr: BitwiseBuiltin*}(loc: felt, value: felt) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY0_felt_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1,0));
    assert carry = 0;
    WARP_DARRAY0_felt_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY0_felt.read(loc, len);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_DARRAY0_felt.write(loc, len, used);
WS_WRITE1(used, value);
    }else{
WS_WRITE1(existing, value);
    }
    return ();
}

func WARP_DARRAY1_Uint256_PUSHV2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr: BitwiseBuiltin*}(loc: felt, value: Uint256) -> (){
    alloc_locals;
    let (len) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
    let (newLen, carry) = uint256_add(len, Uint256(1,0));
    assert carry = 0;
    WARP_DARRAY1_Uint256_LENGTH.write(loc, newLen);
    let (existing) = WARP_DARRAY1_Uint256.read(loc, len);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_DARRAY1_Uint256.write(loc, len, used);
WS_WRITE0(used, value);
    }else{
WS_WRITE0(existing, value);
    }
    return ();
}

func WS0_READ_warp_id{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) ->(val: felt){
    alloc_locals;
    let (read0) = readId(loc);
    return (read0,);
}

func WS1_READ_Uint256{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) ->(val: Uint256){
    alloc_locals;
    let (read0) = WARP_STORAGE.read(loc);
    let (read1) = WARP_STORAGE.read(loc + 1);
    return (Uint256(low=read0,high=read1),);
}

func WS2_READ_felt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt) ->(val: felt){
    alloc_locals;
    let (read0) = WARP_STORAGE.read(loc);
    return (read0,);
}

func ws_dynamic_array_to_calldata0_write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
   loc : felt,
   index : felt,
   len : felt,
   ptr : Uint256*) -> (ptr : Uint256*){
   alloc_locals;
   if (len == index){
       return (ptr,);
   }
   let (index_uint256) = warp_uint256(index);
   let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, index_uint256);
   let (elem) = WS1_READ_Uint256(elem_loc);
   assert ptr[index] = elem;
   return ws_dynamic_array_to_calldata0_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt) -> (dyn_array_struct : cd_dynarray_Uint256){
   alloc_locals;
   let (len_uint256) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
   let len = len_uint256.low + len_uint256.high*128;
   let (ptr : Uint256*) = alloc();
   let (ptr : Uint256*) = ws_dynamic_array_to_calldata0_write(loc, 0, len, ptr);
   let dyn_array_struct = cd_dynarray_Uint256(len, ptr);
   return (dyn_array_struct,);
}

func ws_dynamic_array_to_calldata1_write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
   loc : felt,
   index : felt,
   len : felt,
   ptr : felt*) -> (ptr : felt*){
   alloc_locals;
   if (len == index){
       return (ptr,);
   }
   let (index_uint256) = warp_uint256(index);
   let (elem_loc) = WARP_DARRAY0_felt.read(loc, index_uint256);
   let (elem) = WS2_READ_felt(elem_loc);
   assert ptr[index] = elem;
   return ws_dynamic_array_to_calldata1_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt) -> (dyn_array_struct : cd_dynarray_felt){
   alloc_locals;
   let (len_uint256) = WARP_DARRAY0_felt_LENGTH.read(loc);
   let len = len_uint256.low + len_uint256.high*128;
   let (ptr : felt*) = alloc();
   let (ptr : felt*) = ws_dynamic_array_to_calldata1_write(loc, 0, len, ptr);
   let dyn_array_struct = cd_dynarray_felt(len, ptr);
   return (dyn_array_struct,);
}

func ws_dynamic_array_to_calldata2_write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
   loc : felt,
   index : felt,
   len : felt,
   ptr : felt*) -> (ptr : felt*){
   alloc_locals;
   if (len == index){
       return (ptr,);
   }
   let (index_uint256) = warp_uint256(index);
   let (elem_loc) = WARP_DARRAY0_felt.read(loc, index_uint256);
   let (elem) = WS2_READ_felt(elem_loc);
   assert ptr[index] = elem;
   return ws_dynamic_array_to_calldata2_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt) -> (dyn_array_struct : cd_dynarray_felt){
   alloc_locals;
   let (len_uint256) = WARP_DARRAY0_felt_LENGTH.read(loc);
   let len = len_uint256.low + len_uint256.high*128;
   let (ptr : felt*) = alloc();
   let (ptr : felt*) = ws_dynamic_array_to_calldata2_write(loc, 0, len, ptr);
   let dyn_array_struct = cd_dynarray_felt(len, ptr);
   return (dyn_array_struct,);
}

func ws_dynamic_array_to_calldata3_write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(
   loc : felt,
   index : felt,
   len : felt,
   ptr : Uint256*) -> (ptr : Uint256*){
   alloc_locals;
   if (len == index){
       return (ptr,);
   }
   let (index_uint256) = warp_uint256(index);
   let (elem_loc) = WARP_DARRAY1_Uint256.read(loc, index_uint256);
   let (elem) = WS1_READ_Uint256(elem_loc);
   assert ptr[index] = elem;
   return ws_dynamic_array_to_calldata3_write(loc, index + 1, len, ptr);
}
func ws_dynamic_array_to_calldata3{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc : felt) -> (dyn_array_struct : cd_dynarray_Uint256){
   alloc_locals;
   let (len_uint256) = WARP_DARRAY1_Uint256_LENGTH.read(loc);
   let len = len_uint256.low + len_uint256.high*128;
   let (ptr : Uint256*) = alloc();
   let (ptr : Uint256*) = ws_dynamic_array_to_calldata3_write(loc, 0, len, ptr);
   let dyn_array_struct = cd_dynarray_Uint256(len, ptr);
   return (dyn_array_struct,);
}

func WS_WRITE0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt, value: Uint256) -> (res: Uint256){
    WARP_STORAGE.write(loc, value.low);
    WARP_STORAGE.write(loc + 1, value.high);
    return (value,);
}

func WS_WRITE1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(loc: felt, value: felt) -> (res: felt){
    WARP_STORAGE.write(loc, value);
    return (value,);
}

func cd_to_memory0_elem{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(calldata: felt*, mem_start: felt, length: felt){
    alloc_locals;
    if (length == 0){
        return ();
    }
dict_write{dict_ptr=warp_memory}(mem_start, calldata[0]);
    return cd_to_memory0_elem(calldata + 1, mem_start + 1, length - 1);
}
func cd_to_memory0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(calldata : cd_dynarray_felt) -> (mem_loc: felt){
    alloc_locals;
    let (len256) = felt_to_uint256(calldata.len);
    let (mem_start) = wm_new(len256, Uint256(0x1, 0x0));
    cd_to_memory0_elem(calldata.ptr, mem_start + 2, calldata.len);
    return (mem_start,);
}

func abi_encode0{bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(param0 : felt, param1 : Uint256) -> (result_ptr : felt){
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
  return (mem_ptr,);
}

func abi_encode1{bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(param0 : felt) -> (result_ptr : felt){
  alloc_locals;
  let bytes_index : felt = 0;
  let bytes_offset : felt = 32;
  let (bytes_array : felt*) = alloc();
let (param0256) = felt_to_uint256(param0);
fixed_bytes256_to_felt_dynamic_array(bytes_index, bytes_array, 0, param0256);
let bytes_index = bytes_index + 32;
  let (max_length256) = felt_to_uint256(bytes_offset);
  let (mem_ptr) = wm_new(max_length256, Uint256(0x1, 0x0));
  felt_array_to_warp_memory_array(0, bytes_array, 0, mem_ptr, bytes_offset);
  return (mem_ptr,);
}

func abi_encode2{bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*}(param0 : Uint256) -> (result_ptr : felt){
  alloc_locals;
  let bytes_index : felt = 0;
  let bytes_offset : felt = 32;
  let (bytes_array : felt*) = alloc();
fixed_bytes256_to_felt_dynamic_array(bytes_index, bytes_array, 0, param0);
let bytes_index = bytes_index + 32;
  let (max_length256) = felt_to_uint256(bytes_offset);
  let (mem_ptr) = wm_new(max_length256, Uint256(0x1, 0x0));
  felt_array_to_warp_memory_array(0, bytes_array, 0, mem_ptr, bytes_offset);
  return (mem_ptr,);
}

func _emit_RoyaltiesWithdraw_644800e6{syscall_ptr: felt*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*, keccak_ptr: felt*}(param0 : felt, param1 : Uint256){
   alloc_locals;
   // keys arrays
   let keys_len: felt = 0;
   let (keys: felt*) = alloc();
   //Insert topic
    let (topic256: Uint256) = felt_to_uint256(987259207606944585019788593394946382033643766016660024770182144915957184685);// keccak of event signature: RoyaltiesWithdraw_644800e6(address,uint256)
    let (keys_len: felt) = fixed_bytes256_to_felt_dynamic_array_spl(keys_len, keys, 0, topic256);
   // keys: pack 31 byte felts into a single 248 bit felt
   let (keys_len: felt, keys: felt*) = pack_bytes_felt(31, 1, keys_len, keys);
   // data arrays
   let data_len: felt = 0;
   let (data: felt*) = alloc();
   let (mem_encode: felt) = abi_encode1(param0);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   let (mem_encode: felt) = abi_encode2(param1);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   // data: pack 31 bytes felts into a single 248 bits felt
   let (data_len: felt, data: felt*) = pack_bytes_felt(31, 1, data_len, data);
   emit_event(keys_len, keys, data_len, data);
   return ();
}

func _emit_GetRight_4215fdfe{syscall_ptr: felt*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*, keccak_ptr: felt*}(param0 : Uint256, param1 : Uint256, param2 : felt){
   alloc_locals;
   // keys arrays
   let keys_len: felt = 0;
   let (keys: felt*) = alloc();
   //Insert topic
    let (topic256: Uint256) = felt_to_uint256(1142036649621181151271316921893255235550601329385880426110078296287889148731);// keccak of event signature: GetRight_4215fdfe(uint256,uint256,address)
    let (keys_len: felt) = fixed_bytes256_to_felt_dynamic_array_spl(keys_len, keys, 0, topic256);
   // keys: pack 31 byte felts into a single 248 bit felt
   let (keys_len: felt, keys: felt*) = pack_bytes_felt(31, 1, keys_len, keys);
   // data arrays
   let data_len: felt = 0;
   let (data: felt*) = alloc();
   let (mem_encode: felt) = abi_encode2(param0);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   let (mem_encode: felt) = abi_encode2(param1);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   let (mem_encode: felt) = abi_encode1(param2);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   // data: pack 31 bytes felts into a single 248 bits felt
   let (data_len: felt, data: felt*) = pack_bytes_felt(31, 1, data_len, data);
   emit_event(keys_len, keys, data_len, data);
   return ();
}

func _emit_DepositedNFT_8b187cf9{syscall_ptr: felt*, bitwise_ptr : BitwiseBuiltin*, range_check_ptr : felt, warp_memory : DictAccess*, keccak_ptr: felt*}(param0 : felt, param1 : Uint256){
   alloc_locals;
   // keys arrays
   let keys_len: felt = 0;
   let (keys: felt*) = alloc();
   //Insert topic
    let (topic256: Uint256) = felt_to_uint256(906121910891068680673922152618919759120668638556286754227300728593035886745);// keccak of event signature: DepositedNFT_8b187cf9(address,uint256)
    let (keys_len: felt) = fixed_bytes256_to_felt_dynamic_array_spl(keys_len, keys, 0, topic256);
   // keys: pack 31 byte felts into a single 248 bit felt
   let (keys_len: felt, keys: felt*) = pack_bytes_felt(31, 1, keys_len, keys);
   // data arrays
   let data_len: felt = 0;
   let (data: felt*) = alloc();
   let (mem_encode: felt) = abi_encode1(param0);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   let (mem_encode: felt) = abi_encode2(param1);
   let (encode_bytes_len: felt, encode_bytes: felt*) = wm_to_felt_array(mem_encode);
   let (data_len: felt) = felt_array_concat(encode_bytes_len, 0, encode_bytes, data_len, data);
   // data: pack 31 bytes felts into a single 248 bits felt
   let (data_len: felt, data: felt*) = pack_bytes_felt(31, 1, data_len, data);
   emit_event(keys_len, keys, data_len, data);
   return ();
}

@storage_var
func WARP_DARRAY0_felt(name: felt, index: Uint256) -> (resLoc : felt){
}
@storage_var
func WARP_DARRAY0_felt_LENGTH(name: felt) -> (index: Uint256){
}

@storage_var
func WARP_DARRAY1_Uint256(name: felt, index: Uint256) -> (resLoc : felt){
}
@storage_var
func WARP_DARRAY1_Uint256_LENGTH(name: felt) -> (index: Uint256){
}

@storage_var
func WARP_MAPPING0(name: felt, index: Uint256) -> (resLoc : felt){
}
func WS0_INDEX_Uint256_to_warp_id{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: Uint256) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING0.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING0.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

@storage_var
func WARP_MAPPING1(name: felt, index: felt) -> (resLoc : felt){
}
func WS1_INDEX_felt_to_Uint256{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: felt) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING1.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_MAPPING1.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

@storage_var
func WARP_MAPPING2(name: felt, index: Uint256) -> (resLoc : felt){
}
func WS2_INDEX_Uint256_to_Uint256{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: Uint256) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING2.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 2);
        WARP_MAPPING2.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

@storage_var
func WARP_MAPPING3(name: felt, index: felt) -> (resLoc : felt){
}
func WS3_INDEX_felt_to_warp_id{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: felt) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING3.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING3.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

@storage_var
func WARP_MAPPING4(name: felt, index: Uint256) -> (resLoc : felt){
}
func WS4_INDEX_Uint256_to_felt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: Uint256) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING4.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING4.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}

@storage_var
func WARP_MAPPING5(name: felt, index: felt) -> (resLoc : felt){
}
func WS5_INDEX_felt_to_felt{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(name: felt, index: felt) -> (res: felt){
    alloc_locals;
    let (existing) = WARP_MAPPING5.read(name, index);
    if (existing == 0){
        let (used) = WARP_USED_STORAGE.read();
        WARP_USED_STORAGE.write(used + 1);
        WARP_MAPPING5.write(name, index, used);
        return (used,);
    }else{
        return (existing,);
    }
}


// Contract Def Canary


@event
func GetRight_4215fdfe(_rightid : Uint256, _period : Uint256, _who : felt){
}


@event
func DepositedNFT_8b187cf9(_erc721 : felt, _nftid : Uint256){
}


@event
func RoyaltiesWithdraw_644800e6(owner : felt, amount : Uint256){
}

namespace Canary{

    // Dynamic variables - Arrays and Maps

    const __warp_3_availableRights = 1;

    const __warp_4_highestDeadline = 2;

    const dividends = 3;

    const beforeProposal = 4;

    const __warp_5_rightsOrigin = 5;

    const __warp_6_rightUri = 6;

    const __warp_7_dailyPrice = 7;

    const __warp_8_maxRightsHolders = 8;

    const __warp_9_maxtime = 9;

    const __warp_10_rightsOver = 10;

    const __warp_11_properties = 11;

    const __warp_12_isAvailable = 12;

    const __warp_13_owner = 13;

    const __warp_14_rightHolders = 14;

    const __warp_15_deadline = 15;

    const __warp_16_rightsPeriod = 16;

    const __warp_17_validated = 17;

    // Static variables

    const __warp_0_treasury = 0;

    const period = 2;

    const __warp_1_governanceToken = 4;

    const __warp_2_contractOwner = 5;


    func __warp_while3{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256)-> (__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256){
    alloc_locals;


        
            
            let (__warp_se_0) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
            
            let (__warp_se_1) = WS0_READ_warp_id(__warp_se_0);
            
            let (__warp_se_2) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_1);
            
            let (__warp_se_3) = warp_gt256(__warp_se_2, Uint256(low=0, high=0));
            
            if (__warp_se_3 != 0){
            
                
                    
                    let (__warp_se_4) = WS0_INDEX_Uint256_to_warp_id(__warp_15_deadline, __warp_32__rightid);
                    
                    let (__warp_se_5) = WS0_READ_warp_id(__warp_se_4);
                    
                    let (__warp_se_6) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                    
                    let (__warp_se_7) = WS0_READ_warp_id(__warp_se_6);
                    
                    let (__warp_se_8) = WARP_DARRAY0_felt_IDX(__warp_se_7, __warp_34_j);
                    
                    let (__warp_se_9) = WS2_READ_felt(__warp_se_8);
                    
                    let (__warp_se_10) = WS1_INDEX_felt_to_Uint256(__warp_se_5, __warp_se_9);
                    
                    let (__warp_36_dl) = WS1_READ_Uint256(__warp_se_10);
                    
                    let (__warp_se_11) = WS0_INDEX_Uint256_to_warp_id(__warp_16_rightsPeriod, __warp_32__rightid);
                    
                    let (__warp_se_12) = WS0_READ_warp_id(__warp_se_11);
                    
                    let (__warp_se_13) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                    
                    let (__warp_se_14) = WS0_READ_warp_id(__warp_se_13);
                    
                    let (__warp_se_15) = WARP_DARRAY0_felt_IDX(__warp_se_14, __warp_34_j);
                    
                    let (__warp_se_16) = WS2_READ_felt(__warp_se_15);
                    
                    let (__warp_se_17) = WS1_INDEX_felt_to_Uint256(__warp_se_12, __warp_se_16);
                    
                    let (__warp_37_rp) = WS1_READ_Uint256(__warp_se_17);
                    
                    let (__warp_se_18) = warp_block_timestamp();
                    
                    let (__warp_se_19) = warp_lt256(__warp_36_dl, __warp_se_18);
                    
                    if (__warp_se_19 != 0){
                    
                        
                            
                            let (__warp_se_20) = WS2_INDEX_Uint256_to_Uint256(__warp_7_dailyPrice, __warp_32__rightid);
                            
                            let (__warp_se_21) = WS1_READ_Uint256(__warp_se_20);
                            
                            let (__warp_38_amount) = warp_mul256(__warp_se_21, __warp_37_rp);
                            
                            let (__warp_se_22) = warp_mul256(__warp_38_amount, Uint256(low=500, high=0));
                            
                            let (__warp_se_23) = warp_div256(__warp_se_22, Uint256(low=10000, high=0));
                            
                            let (__warp_se_24) = warp_sub256(__warp_38_amount, __warp_se_23);
                            
                            let (__warp_se_25) = warp_add256(__warp_33_amountToWithdraw, __warp_se_24);
                            
                            let __warp_33_amountToWithdraw = __warp_se_25;
                            
                                
                                let __warp_39_i = Uint256(low=0, high=0);
                                
                                    
                                    let (__warp_tv_0, __warp_tv_1, __warp_tv_2) = __warp_while2(__warp_39_i, __warp_32__rightid, __warp_34_j);
                                    
                                    let __warp_34_j = __warp_tv_2;
                                    
                                    let __warp_32__rightid = __warp_tv_1;
                                    
                                    let __warp_39_i = __warp_tv_0;
                            
                            let (__warp_se_26) = WS0_INDEX_Uint256_to_warp_id(__warp_15_deadline, __warp_32__rightid);
                            
                            let (__warp_se_27) = WS0_READ_warp_id(__warp_se_26);
                            
                            let (__warp_se_28) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_29) = WS0_READ_warp_id(__warp_se_28);
                            
                            let (__warp_se_30) = WARP_DARRAY0_felt_IDX(__warp_se_29, __warp_34_j);
                            
                            let (__warp_se_31) = WS2_READ_felt(__warp_se_30);
                            
                            let (__warp_se_32) = WS1_INDEX_felt_to_Uint256(__warp_se_27, __warp_se_31);
                            
                            WS_WRITE0(__warp_se_32, Uint256(low=0, high=0));
                            
                            let (__warp_se_33) = WS0_INDEX_Uint256_to_warp_id(__warp_16_rightsPeriod, __warp_32__rightid);
                            
                            let (__warp_se_34) = WS0_READ_warp_id(__warp_se_33);
                            
                            let (__warp_se_35) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_36) = WS0_READ_warp_id(__warp_se_35);
                            
                            let (__warp_se_37) = WARP_DARRAY0_felt_IDX(__warp_se_36, __warp_34_j);
                            
                            let (__warp_se_38) = WS2_READ_felt(__warp_se_37);
                            
                            let (__warp_se_39) = WS1_INDEX_felt_to_Uint256(__warp_se_34, __warp_se_38);
                            
                            WS_WRITE0(__warp_se_39, Uint256(low=0, high=0));
                            
                            let (__warp_se_40) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_41) = WS0_READ_warp_id(__warp_se_40);
                            
                            let (__warp_se_42) = WARP_DARRAY0_felt_IDX(__warp_se_41, __warp_34_j);
                            
                            let (__warp_se_43) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_44) = WS0_READ_warp_id(__warp_se_43);
                            
                            let (__warp_se_45) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_46) = WS0_READ_warp_id(__warp_se_45);
                            
                            let (__warp_se_47) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_46);
                            
                            let (__warp_se_48) = warp_sub256(__warp_se_47, Uint256(low=1, high=0));
                            
                            let (__warp_se_49) = WARP_DARRAY0_felt_IDX(__warp_se_44, __warp_se_48);
                            
                            let (__warp_se_50) = WS2_READ_felt(__warp_se_49);
                            
                            WS_WRITE1(__warp_se_42, __warp_se_50);
                            
                            let (__warp_se_51) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                            
                            let (__warp_se_52) = WS0_READ_warp_id(__warp_se_51);
                            
                            WARP_DARRAY0_felt_POP(__warp_se_52);
                            
                            let (__warp_se_53) = WS2_INDEX_Uint256_to_Uint256(__warp_8_maxRightsHolders, __warp_32__rightid);
                            
                            let (__warp_se_54) = WS2_INDEX_Uint256_to_Uint256(__warp_8_maxRightsHolders, __warp_32__rightid);
                            
                            let (__warp_se_55) = WS1_READ_Uint256(__warp_se_54);
                            
                            let (__warp_se_56) = warp_add256(__warp_se_55, Uint256(low=1, high=0));
                            
                            WS_WRITE0(__warp_se_53, __warp_se_56);
                        
                        let (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw) = __warp_while3_if_part2(__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
                        
                        
                        
                        return (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
                    }else{
                    
                        
                        let (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw) = __warp_while3_if_part2(__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
                        
                        
                        
                        return (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
                    }
            }else{
            
                
                    
                    let __warp_32__rightid = __warp_32__rightid;
                    
                    let __warp_34_j = __warp_34_j;
                    
                    let __warp_33_amountToWithdraw = __warp_33_amountToWithdraw;
                    
                    
                    
                    return (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
            }

    }


    func __warp_while3_if_part2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256)-> (__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256){
    alloc_locals;


        
        
        
        let (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw) = __warp_while3_if_part1(__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
        
        
        
        return (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);

    }


    func __warp_while3_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256)-> (__warp_32__rightid : Uint256, __warp_34_j : Uint256, __warp_33_amountToWithdraw : Uint256){
    alloc_locals;


        
        
        
        let (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw) = __warp_while3(__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
        
        
        
        return (__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);

    }


    func __warp_while2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256)-> (__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256){
    alloc_locals;


        
            
            let (__warp_se_57) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
            
            let (__warp_se_58) = WS0_READ_warp_id(__warp_se_57);
            
            let (__warp_se_59) = WARP_DARRAY0_felt_IDX(__warp_se_58, __warp_34_j);
            
            let (__warp_se_60) = WS2_READ_felt(__warp_se_59);
            
            let (__warp_se_61) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_60);
            
            let (__warp_se_62) = WS0_READ_warp_id(__warp_se_61);
            
            let (__warp_se_63) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_62);
            
            let (__warp_se_64) = warp_lt256(__warp_39_i, __warp_se_63);
            
            if (__warp_se_64 != 0){
            
                
                    
                        
                        let (__warp_se_65) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                        
                        let (__warp_se_66) = WS0_READ_warp_id(__warp_se_65);
                        
                        let (__warp_se_67) = WARP_DARRAY0_felt_IDX(__warp_se_66, __warp_34_j);
                        
                        let (__warp_se_68) = WS2_READ_felt(__warp_se_67);
                        
                        let (__warp_se_69) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_68);
                        
                        let (__warp_se_70) = WS0_READ_warp_id(__warp_se_69);
                        
                        let (__warp_se_71) = WARP_DARRAY1_Uint256_IDX(__warp_se_70, __warp_39_i);
                        
                        let (__warp_se_72) = WS1_READ_Uint256(__warp_se_71);
                        
                        let (__warp_se_73) = warp_eq256(__warp_se_72, __warp_32__rightid);
                        
                        if (__warp_se_73 != 0){
                        
                            
                                
                                let (__warp_se_74) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                                
                                let (__warp_se_75) = WS0_READ_warp_id(__warp_se_74);
                                
                                let (__warp_se_76) = WARP_DARRAY0_felt_IDX(__warp_se_75, __warp_34_j);
                                
                                let (__warp_se_77) = WS2_READ_felt(__warp_se_76);
                                
                                let (__warp_se_78) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_77);
                                
                                let (__warp_se_79) = WS0_READ_warp_id(__warp_se_78);
                                
                                let (__warp_se_80) = WARP_DARRAY1_Uint256_IDX(__warp_se_79, __warp_39_i);
                                
                                let (__warp_se_81) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                                
                                let (__warp_se_82) = WS0_READ_warp_id(__warp_se_81);
                                
                                let (__warp_se_83) = WARP_DARRAY0_felt_IDX(__warp_se_82, __warp_34_j);
                                
                                let (__warp_se_84) = WS2_READ_felt(__warp_se_83);
                                
                                let (__warp_se_85) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_84);
                                
                                let (__warp_se_86) = WS0_READ_warp_id(__warp_se_85);
                                
                                let (__warp_se_87) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                                
                                let (__warp_se_88) = WS0_READ_warp_id(__warp_se_87);
                                
                                let (__warp_se_89) = WARP_DARRAY0_felt_IDX(__warp_se_88, __warp_34_j);
                                
                                let (__warp_se_90) = WS2_READ_felt(__warp_se_89);
                                
                                let (__warp_se_91) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_90);
                                
                                let (__warp_se_92) = WS0_READ_warp_id(__warp_se_91);
                                
                                let (__warp_se_93) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_92);
                                
                                let (__warp_se_94) = warp_sub256(__warp_se_93, Uint256(low=1, high=0));
                                
                                let (__warp_se_95) = WARP_DARRAY1_Uint256_IDX(__warp_se_86, __warp_se_94);
                                
                                let (__warp_se_96) = WS1_READ_Uint256(__warp_se_95);
                                
                                WS_WRITE0(__warp_se_80, __warp_se_96);
                                
                                let (__warp_se_97) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
                                
                                let (__warp_se_98) = WS0_READ_warp_id(__warp_se_97);
                                
                                let (__warp_se_99) = WARP_DARRAY0_felt_IDX(__warp_se_98, __warp_34_j);
                                
                                let (__warp_se_100) = WS2_READ_felt(__warp_se_99);
                                
                                let (__warp_se_101) = WS3_INDEX_felt_to_warp_id(__warp_10_rightsOver, __warp_se_100);
                                
                                let (__warp_se_102) = WS0_READ_warp_id(__warp_se_101);
                                
                                WARP_DARRAY1_Uint256_POP(__warp_se_102);
                                
                                let __warp_39_i = __warp_39_i;
                                
                                let __warp_32__rightid = __warp_32__rightid;
                                
                                let __warp_34_j = __warp_34_j;
                                
                                
                                
                                return (__warp_39_i, __warp_32__rightid, __warp_34_j);
                        }else{
                        
                            
                            let (__warp_39_i, __warp_32__rightid, __warp_34_j) = __warp_while2_if_part2(__warp_39_i, __warp_32__rightid, __warp_34_j);
                            
                            
                            
                            return (__warp_39_i, __warp_32__rightid, __warp_34_j);
                        }
            }else{
            
                
                    
                    let __warp_39_i = __warp_39_i;
                    
                    let __warp_32__rightid = __warp_32__rightid;
                    
                    let __warp_34_j = __warp_34_j;
                    
                    
                    
                    return (__warp_39_i, __warp_32__rightid, __warp_34_j);
            }

    }


    func __warp_while2_if_part2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256)-> (__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256){
    alloc_locals;


        
            
            
            
            let (__warp_pse_0) = warp_add256(__warp_39_i, Uint256(low=1, high=0));
            
            let __warp_39_i = __warp_pse_0;
            
            warp_sub256(__warp_pse_0, Uint256(low=1, high=0));
        
        let (__warp_39_i, __warp_32__rightid, __warp_34_j) = __warp_while2_if_part1(__warp_39_i, __warp_32__rightid, __warp_34_j);
        
        
        
        return (__warp_39_i, __warp_32__rightid, __warp_34_j);

    }


    func __warp_while2_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256)-> (__warp_39_i : Uint256, __warp_32__rightid : Uint256, __warp_34_j : Uint256){
    alloc_locals;


        
        
        
        let (__warp_39_i, __warp_32__rightid, __warp_34_j) = __warp_while2(__warp_39_i, __warp_32__rightid, __warp_34_j);
        
        
        
        return (__warp_39_i, __warp_32__rightid, __warp_34_j);

    }


    func __warp_while1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256)-> (__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256){
    alloc_locals;


        
            
            let (__warp_se_103) = get_caller_address();
            
            let (__warp_se_104) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_103);
            
            let (__warp_se_105) = WS0_READ_warp_id(__warp_se_104);
            
            let (__warp_se_106) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_105);
            
            let (__warp_se_107) = warp_lt256(__warp_42_i, __warp_se_106);
            
            if (__warp_se_107 != 0){
            
                
                    
                        
                        let (__warp_se_108) = get_caller_address();
                        
                        let (__warp_se_109) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_108);
                        
                        let (__warp_se_110) = WS0_READ_warp_id(__warp_se_109);
                        
                        let (__warp_se_111) = WARP_DARRAY1_Uint256_IDX(__warp_se_110, __warp_42_i);
                        
                        let (__warp_se_112) = WS1_READ_Uint256(__warp_se_111);
                        
                        let (__warp_se_113) = warp_eq256(__warp_se_112, __warp_40__rightid);
                        
                        if (__warp_se_113 != 0){
                        
                            
                                
                                let __warp_41__rightIndex = __warp_42_i;
                                
                                let __warp_42_i = __warp_42_i;
                                
                                let __warp_40__rightid = __warp_40__rightid;
                                
                                let __warp_41__rightIndex = __warp_41__rightIndex;
                                
                                
                                
                                return (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
                        }else{
                        
                            
                            let (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex) = __warp_while1_if_part2(__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
                            
                            
                            
                            return (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
                        }
            }else{
            
                
                    
                    let __warp_42_i = __warp_42_i;
                    
                    let __warp_40__rightid = __warp_40__rightid;
                    
                    let __warp_41__rightIndex = __warp_41__rightIndex;
                    
                    
                    
                    return (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
            }

    }


    func __warp_while1_if_part2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256)-> (__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256){
    alloc_locals;


        
            
            
            
            let (__warp_pse_1) = warp_add256(__warp_42_i, Uint256(low=1, high=0));
            
            let __warp_42_i = __warp_pse_1;
            
            warp_sub256(__warp_pse_1, Uint256(low=1, high=0));
        
        let (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex) = __warp_while1_if_part1(__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
        
        
        
        return (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);

    }


    func __warp_while1_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256)-> (__warp_42_i : Uint256, __warp_40__rightid : Uint256, __warp_41__rightIndex : Uint256){
    alloc_locals;


        
        
        
        let (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex) = __warp_while1(__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
        
        
        
        return (__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);

    }


    func __warp_while0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256)-> (__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256){
    alloc_locals;


        
            
            let (__warp_se_114) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_3_availableRights);
            
            let (__warp_se_115) = warp_sub256(__warp_se_114, Uint256(low=1, high=0));
            
            let (__warp_se_116) = warp_lt256(__warp_49_i, __warp_se_115);
            
            if (__warp_se_116 != 0){
            
                
                    
                        
                        let (__warp_se_117) = WARP_DARRAY1_Uint256_IDX(__warp_3_availableRights, __warp_49_i);
                        
                        let (__warp_se_118) = WS1_READ_Uint256(__warp_se_117);
                        
                        let (__warp_se_119) = warp_eq256(__warp_se_118, __warp_46__rightid);
                        
                        if (__warp_se_119 != 0){
                        
                            
                                
                                let __warp_48__nftindex = __warp_49_i;
                                
                                let __warp_49_i = __warp_49_i;
                                
                                let __warp_46__rightid = __warp_46__rightid;
                                
                                let __warp_48__nftindex = __warp_48__nftindex;
                                
                                
                                
                                return (__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
                        }else{
                        
                            
                            let (__warp_49_i, __warp_46__rightid, __warp_48__nftindex) = __warp_while0_if_part2(__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
                            
                            
                            
                            return (__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
                        }
            }else{
            
                
                    
                    let __warp_49_i = __warp_49_i;
                    
                    let __warp_46__rightid = __warp_46__rightid;
                    
                    let __warp_48__nftindex = __warp_48__nftindex;
                    
                    
                    
                    return (__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
            }

    }


    func __warp_while0_if_part2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256)-> (__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256){
    alloc_locals;


        
            
            
            
            let (__warp_pse_2) = warp_add256(__warp_49_i, Uint256(low=1, high=0));
            
            let __warp_49_i = __warp_pse_2;
            
            warp_sub256(__warp_pse_2, Uint256(low=1, high=0));
        
        let (__warp_49_i, __warp_46__rightid, __warp_48__nftindex) = __warp_while0_if_part1(__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
        
        
        
        return (__warp_49_i, __warp_46__rightid, __warp_48__nftindex);

    }


    func __warp_while0_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256)-> (__warp_49_i : Uint256, __warp_46__rightid : Uint256, __warp_48__nftindex : Uint256){
    alloc_locals;


        
        
        
        let (__warp_49_i, __warp_46__rightid, __warp_48__nftindex) = __warp_while0(__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
        
        
        
        return (__warp_49_i, __warp_46__rightid, __warp_48__nftindex);

    }


    func __warp_modifier_isNFTOwner_setAvailability_9{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_18__rightid : Uint256, __warp_parameter___warp_46__rightid7 : Uint256, __warp_parameter___warp_47__available8 : felt)-> (){
    alloc_locals;


        
        let (__warp_se_120) = WS4_INDEX_Uint256_to_felt(__warp_13_owner, __warp_18__rightid);
        
        let (__warp_se_121) = WS2_READ_felt(__warp_se_120);
        
        let (__warp_se_122) = get_caller_address();
        
        let (__warp_se_123) = warp_eq(__warp_se_121, __warp_se_122);
        
        with_attr error_message("only the NFT Owner"){
            assert __warp_se_123 = 1;
        }
        
        __warp_original_function_setAvailability_6(__warp_parameter___warp_46__rightid7, __warp_parameter___warp_47__available8);
        
        
        
        return ();

    }


    func __warp_original_function_setAvailability_6{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_46__rightid : Uint256, __warp_47__available : felt)-> (){
    alloc_locals;


        
        let __warp_48__nftindex = Uint256(low=0, high=0);
        
            
            let __warp_49_i = Uint256(low=0, high=0);
            
                
                let (__warp_tv_3, __warp_tv_4, __warp_tv_5) = __warp_while0(__warp_49_i, __warp_46__rightid, __warp_48__nftindex);
                
                let __warp_48__nftindex = __warp_tv_5;
                
                let __warp_46__rightid = __warp_tv_4;
                
                let __warp_49_i = __warp_tv_3;
        
        let (__warp_se_124) = warp_eq(__warp_47__available, 0);
        
        if (__warp_se_124 != 0){
        
            
                
                let (__warp_se_125) = WARP_DARRAY1_Uint256_IDX(__warp_3_availableRights, __warp_48__nftindex);
                
                let (__warp_se_126) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_3_availableRights);
                
                let (__warp_se_127) = warp_sub256(__warp_se_126, Uint256(low=1, high=0));
                
                let (__warp_se_128) = WARP_DARRAY1_Uint256_IDX(__warp_3_availableRights, __warp_se_127);
                
                let (__warp_se_129) = WS1_READ_Uint256(__warp_se_128);
                
                WS_WRITE0(__warp_se_125, __warp_se_129);
                
                WARP_DARRAY1_Uint256_POP(__warp_3_availableRights);
            
            __warp_original_function_setAvailability_6_if_part1(__warp_46__rightid, __warp_47__available);
            
            let __warp_uv5 = ();
            
            
            
            return ();
        }else{
        
            
                
                WARP_DARRAY1_Uint256_PUSHV0(__warp_3_availableRights, __warp_46__rightid);
            
            __warp_original_function_setAvailability_6_if_part1(__warp_46__rightid, __warp_47__available);
            
            let __warp_uv6 = ();
            
            
            
            return ();
        }

    }


    func __warp_original_function_setAvailability_6_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_46__rightid : Uint256, __warp_47__available : felt)-> (){
    alloc_locals;


        
        let (__warp_se_130) = WS4_INDEX_Uint256_to_felt(__warp_12_isAvailable, __warp_46__rightid);
        
        WS_WRITE1(__warp_se_130, __warp_47__available);
        
        
        
        return ();

    }


    func __warp_modifier_isNFTOwner_withdrawNFT_5{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*}(__warp_18__rightid : Uint256, __warp_parameter___warp_40__rightid4 : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_131) = WS4_INDEX_Uint256_to_felt(__warp_13_owner, __warp_18__rightid);
        
        let (__warp_se_132) = WS2_READ_felt(__warp_se_131);
        
        let (__warp_se_133) = get_caller_address();
        
        let (__warp_se_134) = warp_eq(__warp_se_132, __warp_se_133);
        
        with_attr error_message("only the NFT Owner"){
            assert __warp_se_134 = 1;
        }
        
        __warp_original_function_withdrawNFT_3(__warp_parameter___warp_40__rightid4);
        
        
        
        return ();

    }


    func __warp_original_function_withdrawNFT_3{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*}(__warp_40__rightid : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_135) = WS2_INDEX_Uint256_to_Uint256(__warp_4_highestDeadline, __warp_40__rightid);
        
        let (__warp_se_136) = WS1_READ_Uint256(__warp_se_135);
        
        let (__warp_se_137) = warp_block_timestamp();
        
        let (__warp_se_138) = warp_lt256(__warp_se_136, __warp_se_137);
        
        with_attr error_message("highest right deadline should end before withdraw"){
            assert __warp_se_138 = 1;
        }
        
        let (__warp_se_139) = WS4_INDEX_Uint256_to_felt(__warp_12_isAvailable, __warp_40__rightid);
        
        let (__warp_se_140) = WS2_READ_felt(__warp_se_139);
        
        let (__warp_se_141) = warp_eq(__warp_se_140, 0);
        
        with_attr error_message("NFT should be unavailable"){
            assert __warp_se_141 = 1;
        }
        
        let __warp_41__rightIndex = Uint256(low=0, high=0);
        
            
            let __warp_42_i = Uint256(low=0, high=0);
            
                
                let (__warp_tv_6, __warp_tv_7, __warp_tv_8) = __warp_while1(__warp_42_i, __warp_40__rightid, __warp_41__rightIndex);
                
                let __warp_41__rightIndex = __warp_tv_8;
                
                let __warp_40__rightid = __warp_tv_7;
                
                let __warp_42_i = __warp_tv_6;
        
        let (__warp_se_142) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_40__rightid);
        
        let (__warp_se_143) = WS0_READ_warp_id(__warp_se_142);
        
        let (__warp_se_144) = WARP_DARRAY1_Uint256_IDX(__warp_se_143, Uint256(low=0, high=0));
        
        let (__warp_se_145) = WS1_READ_Uint256(__warp_se_144);
        
        let (__warp_43_erc721) = uint256_to_address_felt(__warp_se_145);
        
        let (__warp_se_146) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_40__rightid);
        
        let (__warp_se_147) = WS0_READ_warp_id(__warp_se_146);
        
        let (__warp_se_148) = WARP_DARRAY1_Uint256_IDX(__warp_se_147, Uint256(low=1, high=0));
        
        let (__warp_44_nftid) = WS1_READ_Uint256(__warp_se_148);
        
        _burn(__warp_40__rightid, __warp_41__rightIndex);
        
        let (__warp_se_149) = WS2_INDEX_Uint256_to_Uint256(__warp_4_highestDeadline, __warp_40__rightid);
        
        WS_WRITE0(__warp_se_149, Uint256(low=0, high=0));
        
        let __warp_45_e721 = __warp_43_erc721;
        
        let (__warp_se_150) = get_contract_address();
        
        let (__warp_se_151) = get_caller_address();
        
        IERC721_warped_interface.transferFrom(__warp_45_e721, __warp_se_150, __warp_se_151, __warp_44_nftid);
        
        
        
        return ();

    }


    func __warp_modifier_isNFTOwner_withdrawRoyalties_2{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*, keccak_ptr : felt*}(__warp_18__rightid : Uint256, __warp_parameter___warp_32__rightid1 : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_152) = WS4_INDEX_Uint256_to_felt(__warp_13_owner, __warp_18__rightid);
        
        let (__warp_se_153) = WS2_READ_felt(__warp_se_152);
        
        let (__warp_se_154) = get_caller_address();
        
        let (__warp_se_155) = warp_eq(__warp_se_153, __warp_se_154);
        
        with_attr error_message("only the NFT Owner"){
            assert __warp_se_155 = 1;
        }
        
        __warp_original_function_withdrawRoyalties_0(__warp_parameter___warp_32__rightid1);
        
        
        
        return ();

    }


    func __warp_original_function_withdrawRoyalties_0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*, keccak_ptr : felt*}(__warp_32__rightid : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_156) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_32__rightid);
        
        let (__warp_se_157) = WS0_READ_warp_id(__warp_se_156);
        
        let (__warp_se_158) = WARP_DARRAY0_felt_LENGTH.read(__warp_se_157);
        
        let (__warp_se_159) = warp_gt256(__warp_se_158, Uint256(low=0, high=0));
        
        with_attr error_message("right does not exists"){
            assert __warp_se_159 = 1;
        }
        
        let __warp_33_amountToWithdraw = Uint256(low=0, high=0);
        
        let __warp_34_j = Uint256(low=0, high=0);
        
        let (__warp_35_ct) = WS2_READ_felt(__warp_1_governanceToken);
        
            
            let (__warp_tv_9, __warp_tv_10, __warp_tv_11) = __warp_while3(__warp_32__rightid, __warp_34_j, __warp_33_amountToWithdraw);
            
            let __warp_33_amountToWithdraw = __warp_tv_11;
            
            let __warp_34_j = __warp_tv_10;
            
            let __warp_32__rightid = __warp_tv_9;
        
        let (__warp_se_160) = get_caller_address();
        
        _emit_RoyaltiesWithdraw_644800e6(__warp_se_160, __warp_33_amountToWithdraw);
        
        let (__warp_se_161) = get_caller_address();
        
        Token_warped_interface.transfer(__warp_35_ct, __warp_se_161, __warp_33_amountToWithdraw);
        
        
        
        return ();

    }


    func __warp_constructor_0{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_19__owner : felt)-> (){
    alloc_locals;


        
        WS_WRITE1(__warp_2_contractOwner, __warp_19__owner);
        
        
        
        return ();

    }


    func getRights_if_part1{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*, keccak_ptr : felt*}(__warp_20__rightid : Uint256, __warp_21__period : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_213) = WS0_INDEX_Uint256_to_warp_id(__warp_14_rightHolders, __warp_20__rightid);
        
        let (__warp_se_214) = WS0_READ_warp_id(__warp_se_213);
        
        let (__warp_se_215) = get_caller_address();
        
        WARP_DARRAY0_felt_PUSHV1(__warp_se_214, __warp_se_215);
        
        let (__warp_se_216) = get_caller_address();
        
        _emit_GetRight_4215fdfe(__warp_20__rightid, __warp_21__period, __warp_se_216);
        
        
        
        return ();

    }


    func _mint{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*, keccak_ptr : felt*}(__warp_56__erc721 : felt, __warp_57__nftid : Uint256, __warp_58__amount : Uint256, __warp_59__dailyPrice : Uint256, __warp_60__maxPeriod : Uint256, __warp_61__nftUri : felt)-> (){
    alloc_locals;


        
        let (__warp_se_262) = abi_encode0(__warp_56__erc721, __warp_57__nftid);
        
        let (__warp_62_rightid) = warp_keccak(__warp_se_262);
        
        let (__warp_se_263) = WS2_INDEX_Uint256_to_Uint256(__warp_8_maxRightsHolders, __warp_62_rightid);
        
        WS_WRITE0(__warp_se_263, __warp_58__amount);
        
        let (__warp_se_264) = WS2_INDEX_Uint256_to_Uint256(__warp_7_dailyPrice, __warp_62_rightid);
        
        WS_WRITE0(__warp_se_264, __warp_59__dailyPrice);
        
        let (__warp_se_265) = WS2_INDEX_Uint256_to_Uint256(__warp_9_maxtime, __warp_62_rightid);
        
        WS_WRITE0(__warp_se_265, __warp_60__maxPeriod);
        
        let (__warp_se_266) = WS4_INDEX_Uint256_to_felt(__warp_13_owner, __warp_62_rightid);
        
        let (__warp_se_267) = get_caller_address();
        
        WS_WRITE1(__warp_se_266, __warp_se_267);
        
        let (__warp_se_268) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_62_rightid);
        
        let (__warp_se_269) = WS0_READ_warp_id(__warp_se_268);
        
        let (__warp_se_270) = felt_to_uint256(__warp_56__erc721);
        
        WARP_DARRAY1_Uint256_PUSHV2(__warp_se_269, __warp_se_270);
        
        let (__warp_se_271) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_62_rightid);
        
        let (__warp_se_272) = WS0_READ_warp_id(__warp_se_271);
        
        WARP_DARRAY1_Uint256_PUSHV2(__warp_se_272, __warp_57__nftid);
        
        let (__warp_se_273) = WS0_INDEX_Uint256_to_warp_id(__warp_6_rightUri, __warp_62_rightid);
        
        let (__warp_se_274) = WS0_READ_warp_id(__warp_se_273);
        
        wm_to_storage0(__warp_se_274, __warp_61__nftUri);
        
        let (__warp_se_275) = WS4_INDEX_Uint256_to_felt(__warp_12_isAvailable, __warp_62_rightid);
        
        WS_WRITE1(__warp_se_275, 1);
        
        let (__warp_se_276) = get_caller_address();
        
        let (__warp_se_277) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_276);
        
        let (__warp_se_278) = WS0_READ_warp_id(__warp_se_277);
        
        WARP_DARRAY1_Uint256_PUSHV0(__warp_se_278, __warp_62_rightid);
        
        WARP_DARRAY1_Uint256_PUSHV0(__warp_3_availableRights, __warp_62_rightid);
        
        
        
        return ();

    }


    func _burn{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*, warp_memory : DictAccess*}(__warp_63__rightid : Uint256, __warp_64__rightIndex : Uint256)-> (){
    alloc_locals;


        
        let (__warp_se_279) = WS2_INDEX_Uint256_to_Uint256(__warp_8_maxRightsHolders, __warp_63__rightid);
        
        WS_WRITE0(__warp_se_279, Uint256(low=0, high=0));
        
        let (__warp_se_280) = WS2_INDEX_Uint256_to_Uint256(__warp_7_dailyPrice, __warp_63__rightid);
        
        WS_WRITE0(__warp_se_280, Uint256(low=0, high=0));
        
        let (__warp_se_281) = WS2_INDEX_Uint256_to_Uint256(__warp_9_maxtime, __warp_63__rightid);
        
        WS_WRITE0(__warp_se_281, Uint256(low=0, high=0));
        
        let (__warp_se_282) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_63__rightid);
        
        let (__warp_se_283) = WS0_READ_warp_id(__warp_se_282);
        
        WARP_DARRAY1_Uint256_POP(__warp_se_283);
        
        let (__warp_se_284) = WS0_INDEX_Uint256_to_warp_id(__warp_5_rightsOrigin, __warp_63__rightid);
        
        let (__warp_se_285) = WS0_READ_warp_id(__warp_se_284);
        
        WARP_DARRAY1_Uint256_POP(__warp_se_285);
        
        let (__warp_se_286) = get_caller_address();
        
        let (__warp_se_287) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_286);
        
        let (__warp_se_288) = WS0_READ_warp_id(__warp_se_287);
        
        let (__warp_se_289) = WARP_DARRAY1_Uint256_IDX(__warp_se_288, __warp_64__rightIndex);
        
        let (__warp_se_290) = get_caller_address();
        
        let (__warp_se_291) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_290);
        
        let (__warp_se_292) = WS0_READ_warp_id(__warp_se_291);
        
        let (__warp_se_293) = get_caller_address();
        
        let (__warp_se_294) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_293);
        
        let (__warp_se_295) = WS0_READ_warp_id(__warp_se_294);
        
        let (__warp_se_296) = WARP_DARRAY1_Uint256_LENGTH.read(__warp_se_295);
        
        let (__warp_se_297) = warp_sub256(__warp_se_296, Uint256(low=1, high=0));
        
        let (__warp_se_298) = WARP_DARRAY1_Uint256_IDX(__warp_se_292, __warp_se_297);
        
        let (__warp_se_299) = WS1_READ_Uint256(__warp_se_298);
        
        WS_WRITE0(__warp_se_289, __warp_se_299);
        
        let (__warp_se_300) = get_caller_address();
        
        let (__warp_se_301) = WS3_INDEX_felt_to_warp_id(__warp_11_properties, __warp_se_300);
        
        let (__warp_se_302) = WS0_READ_warp_id(__warp_se_301);
        
        WARP_DARRAY1_Uint256_POP(__warp_se_302);
        
        let (__warp_se_303) = WS0_INDEX_Uint256_to_warp_id(__warp_6_rightUri, __warp_63__rightid);
        
        let (__warp_se_304) = WS0_READ_warp_id(__warp_se_303);
        
        let (__warp_se_305) = WM0_d_arr();
        
        wm_to_storage0(__warp_se_304, __warp_se_305);
        
        let (__warp_se_306) = WS4_INDEX_Uint256_to_felt(__warp_13_owner, __warp_63__rightid);
        
        WS_WRITE1(__warp_se_306, 0);
        
        
        
        return ();

    }

}


    @external
    func getRights{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_20__rightid : Uint256, __warp_21__period : Uint256)-> (){
    alloc_locals;
    let (local keccak_ptr_start : felt*) = alloc();
    let keccak_ptr = keccak_ptr_start;
    let (local warp_memory : DictAccess*) = default_dict_new(0);
    local warp_memory_start: DictAccess* = warp_memory;
    dict_write{dict_ptr=warp_memory}(0,1);
    with warp_memory, keccak_ptr{

        
        warp_external_input_check_int256(__warp_21__period);
        
        warp_external_input_check_int256(__warp_20__rightid);
        
        let (__warp_se_162) = WS4_INDEX_Uint256_to_felt(Canary.__warp_12_isAvailable, __warp_20__rightid);
        
        let (__warp_se_163) = WS2_READ_felt(__warp_se_162);
        
        with_attr error_message("NFT is not available"){
            assert __warp_se_163 = 1;
        }
        
        let (__warp_se_164) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_9_maxtime, __warp_20__rightid);
        
        let (__warp_se_165) = WS1_READ_Uint256(__warp_se_164);
        
        let (__warp_se_166) = warp_ge256(__warp_se_165, __warp_21__period);
        
        with_attr error_message("period is above the max period"){
            assert __warp_se_166 = 1;
        }
        
        let (__warp_se_167) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_8_maxRightsHolders, __warp_20__rightid);
        
        let (__warp_se_168) = WS1_READ_Uint256(__warp_se_167);
        
        let (__warp_se_169) = warp_gt256(__warp_se_168, Uint256(low=0, high=0));
        
        with_attr error_message("limit of right holders reached"){
            assert __warp_se_169 = 1;
        }
        
        let (__warp_se_170) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_16_rightsPeriod, __warp_20__rightid);
        
        let (__warp_se_171) = WS0_READ_warp_id(__warp_se_170);
        
        let (__warp_se_172) = get_caller_address();
        
        let (__warp_se_173) = WS1_INDEX_felt_to_Uint256(__warp_se_171, __warp_se_172);
        
        let (__warp_se_174) = WS1_READ_Uint256(__warp_se_173);
        
        let (__warp_se_175) = warp_eq256(__warp_se_174, Uint256(low=0, high=0));
        
        with_attr error_message("already buy this right"){
            assert __warp_se_175 = 1;
        }
        
        let (__warp_se_176) = warp_gt256(__warp_21__period, Uint256(low=0, high=0));
        
        with_attr error_message("period is equal to 0"){
            assert __warp_se_176 = 1;
        }
        
        let (__warp_22_ct) = WS2_READ_felt(Canary.__warp_1_governanceToken);
        
        let (__warp_se_177) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_8_maxRightsHolders, __warp_20__rightid);
        
        let (__warp_se_178) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_8_maxRightsHolders, __warp_20__rightid);
        
        let (__warp_se_179) = WS1_READ_Uint256(__warp_se_178);
        
        let (__warp_se_180) = warp_sub256(__warp_se_179, Uint256(low=1, high=0));
        
        WS_WRITE0(__warp_se_177, __warp_se_180);
        
        let (__warp_se_181) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_7_dailyPrice, __warp_20__rightid);
        
        let (__warp_se_182) = WS1_READ_Uint256(__warp_se_181);
        
        let (__warp_23_value) = warp_mul256(__warp_se_182, __warp_21__period);
        
        let (__warp_se_183) = get_caller_address();
        
        let (__warp_se_184) = get_contract_address();
        
        Token_warped_interface.transferFrom(__warp_22_ct, __warp_se_183, __warp_se_184, __warp_23_value);
        
        let (__warp_se_185) = WS1_READ_Uint256(Canary.__warp_0_treasury);
        
        let (__warp_se_186) = warp_mul256(__warp_23_value, Uint256(low=500, high=0));
        
        let (__warp_se_187) = warp_div256(__warp_se_186, Uint256(low=10000, high=0));
        
        let (__warp_se_188) = warp_add256(__warp_se_185, __warp_se_187);
        
        WS_WRITE0(Canary.__warp_0_treasury, __warp_se_188);
        
        let (__warp_se_189) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_16_rightsPeriod, __warp_20__rightid);
        
        let (__warp_se_190) = WS0_READ_warp_id(__warp_se_189);
        
        let (__warp_se_191) = get_caller_address();
        
        let (__warp_se_192) = WS1_INDEX_felt_to_Uint256(__warp_se_190, __warp_se_191);
        
        WS_WRITE0(__warp_se_192, __warp_21__period);
        
        let (__warp_se_193) = get_caller_address();
        
        let (__warp_se_194) = WS3_INDEX_felt_to_warp_id(Canary.__warp_10_rightsOver, __warp_se_193);
        
        let (__warp_se_195) = WS0_READ_warp_id(__warp_se_194);
        
        WARP_DARRAY1_Uint256_PUSHV0(__warp_se_195, __warp_20__rightid);
        
        let (__warp_se_196) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_15_deadline, __warp_20__rightid);
        
        let (__warp_se_197) = WS0_READ_warp_id(__warp_se_196);
        
        let (__warp_se_198) = get_caller_address();
        
        let (__warp_se_199) = WS1_INDEX_felt_to_Uint256(__warp_se_197, __warp_se_198);
        
        let (__warp_se_200) = warp_block_timestamp();
        
        let (__warp_se_201) = warp_mul256(Uint256(low=86400, high=0), __warp_21__period);
        
        let (__warp_se_202) = warp_add256(__warp_se_200, __warp_se_201);
        
        WS_WRITE0(__warp_se_199, __warp_se_202);
        
        let (__warp_se_203) = warp_block_timestamp();
        
        let (__warp_se_204) = warp_mul256(Uint256(low=86400, high=0), __warp_21__period);
        
        let (__warp_se_205) = warp_add256(__warp_se_203, __warp_se_204);
        
        let (__warp_se_206) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_4_highestDeadline, __warp_20__rightid);
        
        let (__warp_se_207) = WS1_READ_Uint256(__warp_se_206);
        
        let (__warp_se_208) = warp_gt256(__warp_se_205, __warp_se_207);
        
        if (__warp_se_208 != 0){
        
            
                
                let (__warp_se_209) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_4_highestDeadline, __warp_20__rightid);
                
                let (__warp_se_210) = warp_block_timestamp();
                
                let (__warp_se_211) = warp_mul256(Uint256(low=86400, high=0), __warp_21__period);
                
                let (__warp_se_212) = warp_add256(__warp_se_210, __warp_se_211);
                
                WS_WRITE0(__warp_se_209, __warp_se_212);
            
            Canary.getRights_if_part1(__warp_20__rightid, __warp_21__period);
            
            let __warp_uv0 = ();
            
            default_dict_finalize(warp_memory_start, warp_memory, 0);
            
            finalize_keccak(keccak_ptr_start, keccak_ptr);
            
            return ();
        }else{
        
            
            Canary.getRights_if_part1(__warp_20__rightid, __warp_21__period);
            
            let __warp_uv1 = ();
            
            default_dict_finalize(warp_memory_start, warp_memory, 0);
            
            finalize_keccak(keccak_ptr_start, keccak_ptr);
            
            return ();
        }
    }
    }


    @external
    func depositNFT{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_24__erc721 : felt, __warp_25__nftid : Uint256, __warp_26__dailyPrice : Uint256, __warp_27__maxPeriod : Uint256, __warp_28__amount : Uint256)-> (){
    alloc_locals;
    let (local keccak_ptr_start : felt*) = alloc();
    let keccak_ptr = keccak_ptr_start;
    let (local warp_memory : DictAccess*) = default_dict_new(0);
    local warp_memory_start: DictAccess* = warp_memory;
    dict_write{dict_ptr=warp_memory}(0,1);
    with warp_memory, keccak_ptr{

        
        warp_external_input_check_int256(__warp_28__amount);
        
        warp_external_input_check_int256(__warp_27__maxPeriod);
        
        warp_external_input_check_int256(__warp_26__dailyPrice);
        
        warp_external_input_check_int256(__warp_25__nftid);
        
        warp_external_input_check_address(__warp_24__erc721);
        
        let (__warp_se_217) = warp_neq(__warp_24__erc721, 0);
        
        with_attr error_message("collection address is zero"){
            assert __warp_se_217 = 1;
        }
        
        let __warp_29_e721metadata = __warp_24__erc721;
        
        let (__warp_30_uri_cd_raw_len, __warp_30_uri_cd_raw) = ERC721Metadata_warped_interface.tokenURI(__warp_29_e721metadata, __warp_25__nftid);
        
        local __warp_30_uri_cd : cd_dynarray_felt = cd_dynarray_felt(__warp_30_uri_cd_raw_len, __warp_30_uri_cd_raw);
        
        let (__warp_30_uri) = cd_to_memory0(__warp_30_uri_cd);
        
        Canary._mint(__warp_24__erc721, __warp_25__nftid, __warp_28__amount, __warp_26__dailyPrice, __warp_27__maxPeriod, __warp_30_uri);
        
        let __warp_31_e721 = __warp_24__erc721;
        
        let (__warp_se_218) = get_caller_address();
        
        let (__warp_se_219) = get_contract_address();
        
        IERC721_warped_interface.transferFrom(__warp_31_e721, __warp_se_218, __warp_se_219, __warp_25__nftid);
        
        _emit_DepositedNFT_8b187cf9(__warp_24__erc721, __warp_25__nftid);
        
        default_dict_finalize(warp_memory_start, warp_memory, 0);
        
        finalize_keccak(keccak_ptr_start, keccak_ptr);
        
        return ();
    }
    }


    @external
    func withdrawRoyalties{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_32__rightid : Uint256)-> (){
    alloc_locals;
    let (local keccak_ptr_start : felt*) = alloc();
    let keccak_ptr = keccak_ptr_start;
    let (local warp_memory : DictAccess*) = default_dict_new(0);
    local warp_memory_start: DictAccess* = warp_memory;
    dict_write{dict_ptr=warp_memory}(0,1);
    with warp_memory, keccak_ptr{

        
        warp_external_input_check_int256(__warp_32__rightid);
        
        Canary.__warp_modifier_isNFTOwner_withdrawRoyalties_2(__warp_32__rightid, __warp_32__rightid);
        
        let __warp_uv2 = ();
        
        default_dict_finalize(warp_memory_start, warp_memory, 0);
        
        finalize_keccak(keccak_ptr_start, keccak_ptr);
        
        return ();
    }
    }


    @external
    func withdrawNFT{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_40__rightid : Uint256)-> (){
    alloc_locals;
    let (local warp_memory : DictAccess*) = default_dict_new(0);
    local warp_memory_start: DictAccess* = warp_memory;
    dict_write{dict_ptr=warp_memory}(0,1);
    with warp_memory{

        
        warp_external_input_check_int256(__warp_40__rightid);
        
        Canary.__warp_modifier_isNFTOwner_withdrawNFT_5(__warp_40__rightid, __warp_40__rightid);
        
        let __warp_uv3 = ();
        
        default_dict_finalize(warp_memory_start, warp_memory, 0);
        
        
        return ();
    }
    }


    @external
    func setAvailability{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt, bitwise_ptr : BitwiseBuiltin*}(__warp_46__rightid : Uint256, __warp_47__available : felt)-> (){
    alloc_locals;


        
        warp_external_input_check_bool(__warp_47__available);
        
        warp_external_input_check_int256(__warp_46__rightid);
        
        Canary.__warp_modifier_isNFTOwner_setAvailability_9(__warp_46__rightid, __warp_46__rightid, __warp_47__available);
        
        let __warp_uv4 = ();
        
        
        
        return ();

    }


    @external
    func verifyRight{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_50__rightid : Uint256, __warp_51__platform : felt)-> (){
    alloc_locals;


        
        warp_external_input_check_address(__warp_51__platform);
        
        warp_external_input_check_int256(__warp_50__rightid);
        
        let (__warp_se_220) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_16_rightsPeriod, __warp_50__rightid);
        
        let (__warp_se_221) = WS0_READ_warp_id(__warp_se_220);
        
        let (__warp_se_222) = WS1_INDEX_felt_to_Uint256(__warp_se_221, __warp_51__platform);
        
        let (__warp_se_223) = WS1_READ_Uint256(__warp_se_222);
        
        let (__warp_se_224) = warp_eq256(__warp_se_223, Uint256(low=0, high=0));
        
        with_attr error_message("the platform cannot be the right holder"){
            assert __warp_se_224 = 1;
        }
        
        let (__warp_se_225) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_16_rightsPeriod, __warp_50__rightid);
        
        let (__warp_se_226) = WS0_READ_warp_id(__warp_se_225);
        
        let (__warp_se_227) = get_caller_address();
        
        let (__warp_se_228) = WS1_INDEX_felt_to_Uint256(__warp_se_226, __warp_se_227);
        
        let (__warp_se_229) = WS1_READ_Uint256(__warp_se_228);
        
        let (__warp_se_230) = warp_gt256(__warp_se_229, Uint256(low=0, high=0));
        
        with_attr error_message("sender is not the right holder"){
            assert __warp_se_230 = 1;
        }
        
        let (__warp_se_231) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_15_deadline, __warp_50__rightid);
        
        let (__warp_se_232) = WS0_READ_warp_id(__warp_se_231);
        
        let (__warp_se_233) = get_caller_address();
        
        let (__warp_se_234) = WS1_INDEX_felt_to_Uint256(__warp_se_232, __warp_se_233);
        
        let (__warp_se_235) = WS1_READ_Uint256(__warp_se_234);
        
        let (__warp_se_236) = warp_block_timestamp();
        
        let (__warp_se_237) = warp_gt256(__warp_se_235, __warp_se_236);
        
        with_attr error_message("has exceeded the right time"){
            assert __warp_se_237 = 1;
        }
        
        let (__warp_se_238) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_17_validated, __warp_50__rightid);
        
        let (__warp_se_239) = WS0_READ_warp_id(__warp_se_238);
        
        let (__warp_se_240) = WS3_INDEX_felt_to_warp_id(__warp_se_239, __warp_51__platform);
        
        let (__warp_se_241) = WS0_READ_warp_id(__warp_se_240);
        
        let (__warp_se_242) = get_caller_address();
        
        let (__warp_se_243) = WS5_INDEX_felt_to_felt(__warp_se_241, __warp_se_242);
        
        let (__warp_se_244) = WS2_READ_felt(__warp_se_243);
        
        let (__warp_se_245) = warp_eq(__warp_se_244, 0);
        
        with_attr error_message("rightid and right holder are already validated"){
            assert __warp_se_245 = 1;
        }
        
        let (__warp_se_246) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_17_validated, __warp_50__rightid);
        
        let (__warp_se_247) = WS0_READ_warp_id(__warp_se_246);
        
        let (__warp_se_248) = WS3_INDEX_felt_to_warp_id(__warp_se_247, __warp_51__platform);
        
        let (__warp_se_249) = WS0_READ_warp_id(__warp_se_248);
        
        let (__warp_se_250) = get_caller_address();
        
        let (__warp_se_251) = WS5_INDEX_felt_to_felt(__warp_se_249, __warp_se_250);
        
        WS_WRITE1(__warp_se_251, 1);
        
        let (__warp_52_ct) = WS2_READ_felt(Canary.__warp_1_governanceToken);
        
        let (__warp_se_252) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_7_dailyPrice, __warp_50__rightid);
        
        let (__warp_se_253) = WS1_READ_Uint256(__warp_se_252);
        
        let (__warp_se_254) = warp_div256(__warp_se_253, Uint256(low=2, high=0));
        
        Token_warped_interface.mint(__warp_52_ct, __warp_51__platform, __warp_se_254);
        
        
        
        return ();

    }


    @view
    func verified{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_53__rightid : Uint256, __warp_54__platform : felt)-> (__warp_55 : felt){
    alloc_locals;


        
        warp_external_input_check_address(__warp_54__platform);
        
        warp_external_input_check_int256(__warp_53__rightid);
        
        let (__warp_se_255) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_17_validated, __warp_53__rightid);
        
        let (__warp_se_256) = WS0_READ_warp_id(__warp_se_255);
        
        let (__warp_se_257) = WS3_INDEX_felt_to_warp_id(__warp_se_256, __warp_54__platform);
        
        let (__warp_se_258) = WS0_READ_warp_id(__warp_se_257);
        
        let (__warp_se_259) = get_caller_address();
        
        let (__warp_se_260) = WS5_INDEX_felt_to_felt(__warp_se_258, __warp_se_259);
        
        let (__warp_se_261) = WS2_READ_felt(__warp_se_260);
        
        
        
        return (__warp_se_261,);

    }


    @external
    func setGovernanceToken{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_65__newToken : felt)-> (){
    alloc_locals;


        
        warp_external_input_check_address(__warp_65__newToken);
        
        let (__warp_se_307) = WS2_READ_felt(Canary.__warp_2_contractOwner);
        
        let (__warp_se_308) = get_caller_address();
        
        let (__warp_se_309) = warp_eq(__warp_se_307, __warp_se_308);
        
        assert __warp_se_309 = 1;
        
        WS_WRITE1(Canary.__warp_1_governanceToken, __warp_65__newToken);
        
        
        
        return ();

    }


    @view
    func currentTreasury{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}()-> (__warp_66 : Uint256){
    alloc_locals;


        
        let (__warp_se_310) = WS1_READ_Uint256(Canary.__warp_0_treasury);
        
        
        
        return (__warp_se_310,);

    }


    @view
    func dailyPriceOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_67__rightid : Uint256)-> (__warp_68 : Uint256){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_67__rightid);
        
        let (__warp_se_311) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_7_dailyPrice, __warp_67__rightid);
        
        let (__warp_se_312) = WS1_READ_Uint256(__warp_se_311);
        
        
        
        return (__warp_se_312,);

    }


    @view
    func availableRightsOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_69__rightid : Uint256)-> (__warp_70 : Uint256){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_69__rightid);
        
        let (__warp_se_313) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_8_maxRightsHolders, __warp_69__rightid);
        
        let (__warp_se_314) = WS1_READ_Uint256(__warp_se_313);
        
        
        
        return (__warp_se_314,);

    }


    @view
    func maxPeriodOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_71__rightid : Uint256)-> (__warp_72 : Uint256){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_71__rightid);
        
        let (__warp_se_315) = WS2_INDEX_Uint256_to_Uint256(Canary.__warp_9_maxtime, __warp_71__rightid);
        
        let (__warp_se_316) = WS1_READ_Uint256(__warp_se_315);
        
        
        
        return (__warp_se_316,);

    }


    @view
    func rightsPeriodOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_73__rightid : Uint256, __warp_74__holder : felt)-> (__warp_75 : Uint256){
    alloc_locals;


        
        warp_external_input_check_address(__warp_74__holder);
        
        warp_external_input_check_int256(__warp_73__rightid);
        
        let (__warp_se_317) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_16_rightsPeriod, __warp_73__rightid);
        
        let (__warp_se_318) = WS0_READ_warp_id(__warp_se_317);
        
        let (__warp_se_319) = WS1_INDEX_felt_to_Uint256(__warp_se_318, __warp_74__holder);
        
        let (__warp_se_320) = WS1_READ_Uint256(__warp_se_319);
        
        
        
        return (__warp_se_320,);

    }


    @view
    func rightsOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_76__rightsHolder : felt)-> (__warp_77_len : felt, __warp_77 : Uint256*){
    alloc_locals;


        
        warp_external_input_check_address(__warp_76__rightsHolder);
        
        let (__warp_se_321) = WS3_INDEX_felt_to_warp_id(Canary.__warp_10_rightsOver, __warp_76__rightsHolder);
        
        let (__warp_se_322) = WS0_READ_warp_id(__warp_se_321);
        
        let (__warp_se_323) = ws_dynamic_array_to_calldata0(__warp_se_322);
        
        
        
        return (__warp_se_323.len, __warp_se_323.ptr,);

    }


    @view
    func propertiesOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_78__owner : felt)-> (__warp_79_len : felt, __warp_79 : Uint256*){
    alloc_locals;


        
        warp_external_input_check_address(__warp_78__owner);
        
        let (__warp_se_324) = WS3_INDEX_felt_to_warp_id(Canary.__warp_11_properties, __warp_78__owner);
        
        let (__warp_se_325) = WS0_READ_warp_id(__warp_se_324);
        
        let (__warp_se_326) = ws_dynamic_array_to_calldata0(__warp_se_325);
        
        
        
        return (__warp_se_326.len, __warp_se_326.ptr,);

    }


    @view
    func getAvailableNFTs{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}()-> (__warp_80_len : felt, __warp_80 : Uint256*){
    alloc_locals;


        
        let (__warp_se_327) = ws_dynamic_array_to_calldata0(Canary.__warp_3_availableRights);
        
        
        
        return (__warp_se_327.len, __warp_se_327.ptr,);

    }


    @view
    func rightHoldersOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_81__rightid : Uint256)-> (__warp_82_len : felt, __warp_82 : felt*){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_81__rightid);
        
        let (__warp_se_328) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_14_rightHolders, __warp_81__rightid);
        
        let (__warp_se_329) = WS0_READ_warp_id(__warp_se_328);
        
        let (__warp_se_330) = ws_dynamic_array_to_calldata1(__warp_se_329);
        
        
        
        return (__warp_se_330.len, __warp_se_330.ptr,);

    }


    @view
    func holderDeadline{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_83__rightid : Uint256, __warp_84__holder : felt)-> (__warp_85 : Uint256){
    alloc_locals;


        
        warp_external_input_check_address(__warp_84__holder);
        
        warp_external_input_check_int256(__warp_83__rightid);
        
        let (__warp_se_331) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_15_deadline, __warp_83__rightid);
        
        let (__warp_se_332) = WS0_READ_warp_id(__warp_se_331);
        
        let (__warp_se_333) = WS1_INDEX_felt_to_Uint256(__warp_se_332, __warp_84__holder);
        
        let (__warp_se_334) = WS1_READ_Uint256(__warp_se_333);
        
        
        
        return (__warp_se_334,);

    }


    @view
    func ownerOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_86__rightid : Uint256)-> (__warp_87 : felt){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_86__rightid);
        
        let (__warp_se_335) = WS4_INDEX_Uint256_to_felt(Canary.__warp_13_owner, __warp_86__rightid);
        
        let (__warp_se_336) = WS2_READ_felt(__warp_se_335);
        
        
        
        return (__warp_se_336,);

    }


    @view
    func availabilityOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_88__rightid : Uint256)-> (__warp_89 : felt){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_88__rightid);
        
        let (__warp_se_337) = WS4_INDEX_Uint256_to_felt(Canary.__warp_12_isAvailable, __warp_88__rightid);
        
        let (__warp_se_338) = WS2_READ_felt(__warp_se_337);
        
        
        
        return (__warp_se_338,);

    }


    @view
    func rightURI{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_90__rightid : Uint256)-> (__warp_91_len : felt, __warp_91 : felt*){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_90__rightid);
        
        let (__warp_se_339) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_6_rightUri, __warp_90__rightid);
        
        let (__warp_se_340) = WS0_READ_warp_id(__warp_se_339);
        
        let (__warp_se_341) = ws_dynamic_array_to_calldata2(__warp_se_340);
        
        
        
        return (__warp_se_341.len, __warp_se_341.ptr,);

    }


    @view
    func originOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_92__rightid : Uint256)-> (__warp_93_len : felt, __warp_93 : Uint256*){
    alloc_locals;


        
        warp_external_input_check_int256(__warp_92__rightid);
        
        let (__warp_se_342) = WS0_INDEX_Uint256_to_warp_id(Canary.__warp_5_rightsOrigin, __warp_92__rightid);
        
        let (__warp_se_343) = WS0_READ_warp_id(__warp_se_342);
        
        let (__warp_se_344) = ws_dynamic_array_to_calldata3(__warp_se_343);
        
        
        
        return (__warp_se_344.len, __warp_se_344.ptr,);

    }


    @constructor
    func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr : felt}(__warp_19__owner : felt){
    alloc_locals;
    WARP_USED_STORAGE.write(23);
    WARP_NAMEGEN.write(17);


        
        warp_external_input_check_address(__warp_19__owner);
        
        Canary.__warp_constructor_0(__warp_19__owner);
        
        
        
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
func mint(_platform : felt, _amount : Uint256)-> (){
}
func burn(_platform : felt, _amount : Uint256)-> (){
}
func transfer(_to : felt, _value : Uint256)-> (success : felt){
}
func transferFrom(_from : felt, _to : felt, _value : Uint256)-> (success : felt){
}
}


// Contract Def ERC721Metadata@interface


@contract_interface
namespace ERC721Metadata_warped_interface{
func tokenURI(_tokenId : Uint256)-> (__warp_0_len : felt, __warp_0 : felt*){
}
}


// Contract Def IERC721@interface


@contract_interface
namespace IERC721_warped_interface{
func transferFrom(_from : felt, _to : felt, _tokenId : Uint256)-> (){
}
}