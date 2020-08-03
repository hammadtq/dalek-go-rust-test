extern crate byteorder;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use std::mem;
use bulletproofs::{PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto,RistrettoPoint};

pub fn generate_pc() -> CompressedRistretto {

        let gens = PedersenGens::default();

        //PedersenGens::default takes a struct of B as B: RISTRETTO_BASEPOINT_POINT which is similar to (g) basepoint in 
        //gtank's go implementation as well, however, it takes a sha3_512 of (g) to make the (h) point which is not similar to
        //go's (h) point.
        //https://github.com/dalek-cryptography/bulletproofs/blob/1a10ce1a5b87299014658770346b376a858e7691/src/generators.rs#L34
        //https://github.com/dalek-cryptography/bulletproofs/blob/1a10ce1a5b87299014658770346b376a858e7691/src/generators.rs#L46
        
        return  gens.B_blinding.compress();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn h_point_test() {
        let h_base_point = generate_pc();
        let h_generated_by_go: [i32; 32] = [82, 104, 110, 237, 93, 65, 230, 142, 34, 146, 34, 70, 230, 193, 209, 250, 77, 4, 44, 188, 201, 141, 147, 216, 167, 94, 216, 144, 249, 218, 102, 36];

        println!("h_base_point: {:?}", h_base_point);
        println!("h_generated_by_go: {:?}", h_generated_by_go);
    }

    #[test]
    fn uniform_bytes_test() {

        let mut buf = [0; 64];
        LittleEndian::write_u64(&mut buf, 41);

        println!("original {:?}", RistrettoPoint::from_uniform_bytes(&buf).compress());
        assert_eq!(41, LittleEndian::read_u64(&buf));
    }
    
}
