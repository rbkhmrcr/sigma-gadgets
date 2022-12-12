use elliptic_curves;
fn main() {
    println!("Hello, world!");
}


fn NISA_prove(param : Param, g : GroupAffine, P : GroupAffine, c : Field, a : &[Field]) -> Proof { 
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
