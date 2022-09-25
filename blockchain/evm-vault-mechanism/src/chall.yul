object "chall" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            if lt(calldatasize(), 8) {
                revert(0, 0)
            }

            function A(inp) -> res {
                let v := add(inp, 0x69b135a06c3)
                v := mul(v, 0x80)
                v := xor(v, 0xb3abdcef1f1)
                res := iszero(eq(0x346d81803d471, v))
            }

            function B(inp) -> res {
                mstore(15, inp)
                let h := keccak256(15, 4)
                res := iszero(eq(shr(0xc8, h), 0xfd28448c97d19c))
            }

            function C(inp) -> res {
                let c := caller()
                let b := balance(c)
                let s := extcodesize(c)
                let h := extcodehash(c)
                let hb := shr(24, and(h, 0xff000000))
                extcodecopy(c, 7, 11, 4)
                let hh := keccak256(7, 4)
                let hhh := and(hh, 0xff)
                res := iszero(mul(mul(mul(eq(and(c, 0xff), 0x77), gt(b, 1000000000000000000)), eq(s, hb)), eq(hhh, 0x77)))
            }

            function D(inp) -> res {
                let x := shr(8, and(inp, 0xffff00))
                let y := mul(2, add(shl(7, x), 13))
                let z := mul(0x101, and(shr(24, inp), 0xff))
                let h := blockhash(sub(number(), add(3, and(mul(2, and(inp, 0xff)), 0xff))))
                res := iszero(eq(0, xor(z, add(y, h))))
            }

            function E(inp) -> res {
                let h := extcodehash(address())
                mstore(7, h)
                let y := 0
                let c := 0
                for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                    if eq(and(shr(i, inp), 1), 1) {
                        y := add(y, and(shr(mul(i, 8), mload(7)), 0xff))
                        c := add(c, 1)
                    }
                }
                res := mul(eq(777, mod(y, 1337)), eq(c, 17))
            }

            function F(inp) -> res {
                res := 0
            }

            let choice := shr(0xe0, calldataload(0))
            let inp := shr(0xe0, calldataload(4))

            switch choice
            case 0x76726679 {
                let s := sload(0x1337)
                if eq(s, 0xff) {
                    sstore(0x736f6c766564, 1)
                }
            }
            case 0x41414141 {
                let r := A(inp)
                if iszero(r) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 74))
                }
            }
            case 0x42424242 {
                let r := B(inp)
                if iszero(r) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 209))
                }
            }
            case 0x43434343 {
                let r := C(inp)
                if iszero(r) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 100))
                }
            }
            case 0x44444444 {
                let r := D(inp)
                if iszero(r) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 178))
                }
            }
            case 0x45454545 {
                let r := E(inp)
                if eq(r, 1) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 99))
                }
            }
            case 0x46464646 {
                let r := F(inp)
                if iszero(r) {
                    let s := sload(0x1337)                
                    sstore(0x1337, xor(s, 196))
                }
            }
            default {
                revert(0, 0)
            }

            stop()
        }
    }
}
