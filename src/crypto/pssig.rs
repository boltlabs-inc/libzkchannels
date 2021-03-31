// pssig.rs
// PS Sigs - Pointcheval Sanders ('06)
use super::*;
use crypto::ped92::{CSMultiParams, Commitment};
use ff::PrimeField;
use pairing::{CurveProjective, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use util;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(
    deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>, <E as pairing::Engine>::G2: serde::Deserialize<'de>"
))]
pub struct PublicParams<E: Engine> {
    pub g1: E::G1,
    pub g2: E::G2,
}

impl<E: Engine> PartialEq for PublicParams<E> {
    fn eq(&self, other: &PublicParams<E>) -> bool {
        self.g1 == other.g1 && self.g2 == other.g2
    }
}

impl<E: Engine> PublicParams<E> {
    pub fn from_slice<'de>(ser_g1: &'de [u8], ser_g2: &'de [u8]) -> Self
    where
        <E as pairing::Engine>::G1: serde::Deserialize<'de>,
        <E as pairing::Engine>::G2: serde::Deserialize<'de>,
    {
        // TODO: handle malformed input errors
        let g1: E::G1 = serde_json::from_slice(ser_g1).unwrap();
        let g2: E::G2 = serde_json::from_slice(ser_g2).unwrap();

        PublicParams { g1, g2 }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>")
)]
pub struct SecretKey<E: Engine> {
    pub x: E::Fr,
    pub y: Vec<E::Fr>,
    pub X: E::G1,
}

impl<E: Engine> fmt::Display for SecretKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut y_str = String::new();
        let mut i = 0;
        for y in self.y.iter() {
            y_str = format!("{}\n{} => {}", y_str, i, y);
            i += 1;
        }

        write!(f, "SK : \nx={},\ny=[{}\n]", self.x, y_str)
    }
}

impl<E: Engine> PartialEq for SecretKey<E> {
    fn eq(&self, other: &SecretKey<E>) -> bool {
        self.x == other.x && util::is_vec_fr_equal::<E>(&self.y, &other.y)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(deserialize = "<E as pairing::Engine>::G2: serde::Deserialize<'de>"))]
pub struct PublicKey<E: Engine> {
    pub X: E::G2,
    pub Y: Vec<E::G2>,
}

impl<E: Engine> fmt::Display for PublicKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut y_s = String::new();
        let mut i = 0;
        for y in self.Y.iter() {
            y_s = format!("{}\n{} => {}", y_s, i, y);
            i += 1;
        }

        write!(f, "PK : \nX={},\nY=[{}\n]", self.X, y_s)
    }
}

impl<E: Engine> PartialEq for PublicKey<E> {
    fn eq(&self, other: &PublicKey<E>) -> bool {
        self.X == other.X && util::is_vec_g2_equal::<E>(&self.Y, &other.Y)
    }
}

impl<E: Engine> PublicKey<E> {
    pub fn from_slice<'de>(
        ser_x: &'de [u8],
        ser_y: &'de [u8],
        y_len: usize,
        num_elems: usize,
    ) -> Self
    where
        <E as pairing::Engine>::G2: serde::Deserialize<'de>,
    {
        let X: E::G2 = serde_json::from_slice(ser_x).unwrap();
        let mut Y: Vec<E::G2> = Vec::new();
        let mut start_pos = 0;
        let mut end_pos = y_len;
        for _ in 0..num_elems {
            let y = serde_json::from_slice(&ser_y[start_pos..end_pos]).unwrap();
            start_pos = end_pos;
            end_pos += y_len;
            Y.push(y);
        }
        PublicKey { X, Y }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(serialize = "<E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(bound(deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>"))]
pub struct BlindPublicKey<E: Engine> {
    pub X2: E::G2,
    pub Y1: Vec<E::G1>,
    pub Y2: Vec<E::G2>,
}

impl<E: Engine> fmt::Display for BlindPublicKey<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut y1_str = String::new();
        for y in self.Y1.iter() {
            y1_str = format!("{}\n{}", y1_str, y);
        }

        let mut y2_str = String::new();
        for y in self.Y2.iter() {
            y2_str = format!("{}\n{}", y2_str, y);
        }

        write!(
            f,
            "Blind PK : \nX2{},\nY1=[{}\n],\nY2=[{}\n]",
            self.X2, y1_str, y2_str
        )
    }
}

impl<E: Engine> PartialEq for BlindPublicKey<E> {
    fn eq(&self, other: &BlindPublicKey<E>) -> bool {
        self.X2 == other.X2
            && util::is_vec_g1_equal::<E>(&self.Y1, &other.Y1)
            && util::is_vec_g2_equal::<E>(&self.Y2, &other.Y2)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Signature<E: Engine> {
    pub h: E::G1,
    pub H: E::G1,
}

impl<E: Engine> PartialEq for Signature<E> {
    fn eq(&self, other: &Signature<E>) -> bool {
        self.h == other.h && self.H == other.H
    }
}

impl<E: Engine> Signature<E> {
    pub fn from_slice<'de>(ser_h: &'de [u8], ser_H: &'de [u8]) -> Self
    where
        <E as pairing::Engine>::G1: serde::Deserialize<'de>,
    {
        // TODO: handle malformed input errors
        let h: E::G1 = serde_json::from_slice(ser_h).unwrap();
        let H: E::G1 = serde_json::from_slice(ser_H).unwrap();

        Signature { h, H }
    }

    pub fn serialize_compact(&self) -> Vec<u8>
    where
        <E as pairing::Engine>::G1: serde::Serialize,
    {
        let mut s = Vec::new();
        let h1 = serde_json::to_string(&self.h).unwrap();
        let last = h1.len() - 1;
        let b = hex::decode(&h1[1..last]).unwrap();
        s.extend_from_slice(&b);

        let h2 = serde_json::to_string(&self.H).unwrap();
        let last = h2.len() - 1;
        let b = hex::decode(&h2[1..last]).unwrap();
        s.extend_from_slice(&b);
        return s;
    }
}

#[derive(Clone)]
pub struct KeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct BlindKeyPair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: BlindPublicKey<E>,
}

#[derive(Clone)]
pub struct ProofState<E: Engine> {
    pub v: E::Fr,
    pub t: Vec<E::Fr>,
    pub tt: E::Fr,
    pub a: E::Fqk,
    pub blindSig: Signature<E>,
}

impl<E: Engine> ProofState<E> {
    #[cfg(test)]
    fn fs_challenge(&self, mpk: &PublicParams<E>) -> E::Fr
    where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        let mut transcript: Vec<u8> = Vec::new();
        transcript.extend(
            serde_json::to_value(&mpk.g1)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );
        transcript.extend(
            serde_json::to_value(&mpk.g2)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );
        transcript.extend(
            serde_json::to_value(&self.a)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );

        util::hash_to_fr::<E>(transcript)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize, \
                           <E as pairing::Engine>::Fqk: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::Fqk: serde::Deserialize<'de>")
)]
pub struct SignatureProof<E: Engine> {
    pub zsig: Vec<E::Fr>,
    pub zv: E::Fr,
    pub a: E::Fqk,
}

impl<E: Engine> SecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let mut y: Vec<E::Fr> = Vec::new();
        for _i in 0..l {
            let _y = E::Fr::rand(csprng);
            y.push(_y);
        }
        let x = E::Fr::rand(csprng);
        // X1 = g1 ^ x
        let mut X = mpk.g1;
        X.mul_assign(x.clone());
        SecretKey { x: x, y: y, X: X }
    }

    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        let h = E::G1::rand(csprng);
        let mut s = E::Fr::zero();
        // check vector length first
        assert!(self.y.len() >= message.len());
        for i in 0..message.len() {
            // s = s + (self.y[i] * message[i]);
            let mut res_yi = self.y[i];
            res_yi.mul_assign(&message[i]);
            s.add_assign(&res_yi);
        }

        // h ^ (x + s)
        let mut res_x = self.x;
        res_x.add_assign(&s);

        let mut H = h;
        H.mul_assign(res_x);

        Signature { h: h, H: H }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]

pub struct PartialProducts<E: Engine> {
    pub Ys: Vec<E::G2>,
    pub Ls: Vec<E::G2>,
}

///
/// Interface for CL PS signature variant
///
impl<E: Engine> PublicKey<E> {
    pub fn from_secret(mpk: &PublicParams<E>, secret: &SecretKey<E>) -> Self {
        let mut Y: Vec<E::G2> = Vec::new();
        for i in 0..secret.y.len() {
            // Y[i] = g2 ^ y[i]
            let mut g2 = mpk.g2;
            g2.mul_assign(secret.y[i]);
            Y.push(g2);
        }
        // X = g2 ^ x
        let mut X = mpk.g2;
        X.mul_assign(secret.x);
        PublicKey { X: X, Y: Y }
    }

    pub fn verify(
        &self,
        mpk: &PublicParams<E>,
        message: &Vec<E::Fr>,
        signature: &Signature<E>,
    ) -> bool {
        let mut L = E::G2::zero();
        let mut l = self.Y.len();
        let diff = (l - message.len());

        l = match diff > 0 {
            true => message.len(),
            false => l,
        };

        for i in 0..l {
            if i < message.len() {
                // bounds check on message vector
                // L = L + self.Y[i].mul(message[i]);
                let mut Y = self.Y[i];
                Y.mul_assign(message[i]); // Y_i ^ m_i
                L.add_assign(&Y); // L += Y_i ^m_i
            }
        }

        let mut X2 = self.X;
        X2.add_assign(&L); // X2 = X + L
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);
        signature.h != E::G1::one() && lhs == rhs
    }

    pub fn debug_verify(
        &self,
        mpk: &PublicParams<E>,
        message: &Vec<E::Fr>,
        signature: &Signature<E>,
    ) -> (bool, PartialProducts<E>) {
        let mut L = E::G2::zero();
        let mut l = self.Y.len();
        let diff = (l - message.len());
        let mut pp1 = Vec::new();
        let mut pp2 = Vec::new();

        l = match diff > 0 {
            true => message.len(),
            false => l,
        };

        for i in 0..l {
            if i < message.len() {
                // bounds check on message vector
                // L = L + self.Y[i].mul(message[i]);
                let mut Y = self.Y[i];
                Y.mul_assign(message[i]); // Y_i ^ m_i
                pp1.push(Y.clone());
                L.add_assign(&Y); // L += Y_i ^m_i
                pp2.push(L.clone()); // sum so far
            }
        }

        let mut X2 = self.X;
        X2.add_assign(&L); // X2 = X + L
        pp2.push(X2.clone());
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);
        let pp = PartialProducts { Ys: pp1, Ls: pp2 };
        return ((signature.h != E::G1::one() && lhs == rhs), pp);
    }
}

///
/// Interface for blind sigs based on CL PS variant
///
impl<E: Engine> BlindPublicKey<E> {
    pub fn from_secret(mpk: &PublicParams<E>, secret: &SecretKey<E>) -> Self {
        let mut Y1: Vec<E::G1> = Vec::new();
        let mut Y2: Vec<E::G2> = Vec::new();
        for i in 0..secret.y.len() {
            // Y[i] = g2 ^ y[i]
            let mut g1y = mpk.g1;
            let mut g2y = mpk.g2;
            g1y.mul_assign(secret.y[i]);
            g2y.mul_assign(secret.y[i]);
            Y1.push(g1y);
            Y2.push(g2y);
        }
        // X2 = g2 ^ x
        let mut X2 = mpk.g2;
        X2.mul_assign(secret.x);
        BlindPublicKey {
            X2: X2,
            Y1: Y1,
            Y2: Y2,
        }
    }

    pub fn get_pub_key(&self) -> PublicKey<E> {
        PublicKey {
            X: self.X2.clone(),
            Y: self.Y2.clone(),
        }
    }

    pub fn verify(
        &self,
        mpk: &PublicParams<E>,
        message: &Vec<E::Fr>,
        signature: &Signature<E>,
    ) -> bool {
        let mut L = E::G2::zero();
        let l = self.Y2.len();
        //println!("verify - m.len = {}, l = {}", message.len(), l);
        assert!(message.len() <= l + 1);

        let last_elem = match l >= message.len() {
            true => message.len() - 1,
            false => l,
        };

        let l = match l >= message.len() {
            true => message.len() - 1,
            false => l,
        };

        for i in 0..l {
            // L = L + self.Y[i].mul(message[i]);
            let mut Y = self.Y2[i];
            Y.mul_assign(message[i]); // Y_i ^ m_i
            L.add_assign(&Y); // L += Y_i ^m_i
        }

        // Y_(l+1) ^ t
        let mut Yt = mpk.g2.clone();
        Yt.mul_assign(message[last_elem]);
        L.add_assign(&Yt);

        let mut X2 = self.X2.clone();
        X2.add_assign(&L); // X2 = X + L
        let lhs = E::pairing(signature.h, X2);
        let rhs = E::pairing(signature.H, mpk.g2);

        signature.h != E::G1::one() && lhs == rhs
    }

    /// verify a blinded signature without unblinding it first
    pub fn verify_blind(
        &self,
        mpk: &PublicParams<E>,
        message: &Vec<E::Fr>,
        bf: &E::Fr,
        signature: &Signature<E>,
    ) -> bool {
        let mut m = message.clone();
        let t = bf.clone();
        m.push(t);
        self.verify(mpk, &m, signature)
    }

    /// Verify a proof of knowledge of a signature
    /// Takes in a proof generated by prove_response(), a blind signature, and a challenge
    /// outputs: boolean
    pub fn verify_proof(
        &self,
        mpk: &PublicParams<E>,
        blindSig: Signature<E>,
        p: SignatureProof<E>,
        challenge: E::Fr,
    ) -> bool {
        let mut gx = E::pairing(blindSig.h, self.X2);
        gx = gx.pow(challenge.into_repr());
        for j in 0..self.Y2.len() {
            let mut gy = E::pairing(blindSig.h, self.Y2[j]);
            gy = gy.pow(p.zsig[j].into_repr());
            gx.mul_assign(&gy);
        }
        let mut h = E::pairing(blindSig.h, mpk.g2);
        h = h.pow(p.zv.into_repr());
        gx.mul_assign(&h);
        let mut g = E::pairing(blindSig.H, mpk.g2);
        g = g.pow(challenge.into_repr());
        g.mul_assign(&p.a);
        gx == g
    }

    pub fn blind<R: Rng>(
        &self,
        csprng: &mut R,
        bf: &E::Fr,
        signature: &Signature<E>,
    ) -> Signature<E> {
        let r = E::Fr::rand(csprng);
        let t = bf.clone();
        let mut h1 = signature.h;
        h1.mul_assign(r); // sigma1 ^ r

        let mut h = signature.h;
        let mut H1 = signature.H;
        h.mul_assign(t); // sigma1 ^ t (blinding factor)
        H1.add_assign(&h); // (sigma2 * sigma1 ^ t)

        // (sigma2 * sigma1 ^ t) ^ r
        H1.mul_assign(r);
        Signature { h: h1, H: H1 }
    }

    pub fn unblind(&self, bf: &E::Fr, signature: &Signature<E>) -> Signature<E> {
        let mut H = signature.h;
        let mut inv_bf = bf.clone();
        inv_bf.negate();

        // sigma2 / sigma1 ^ t
        H.mul_assign(inv_bf);
        H.add_assign(&signature.H);

        Signature {
            h: signature.h,
            H: H,
        }
    }

    /// prove knowledge of a signature: commitment phase
    /// returns the proof state, including commitment a and a blind signature blindSig
    pub fn prove_commitment<R: Rng>(
        &self,
        rng: &mut R,
        mpk: &PublicParams<E>,
        signature: &Signature<E>,
        tOptional: Option<Vec<E::Fr>>,
        ttOptional: Option<E::Fr>,
    ) -> ProofState<E> {
        let v = E::Fr::rand(rng);
        let blindSig = self.blind(rng, &v, signature);
        let mut t = tOptional.unwrap_or(Vec::<E::Fr>::with_capacity(self.Y2.len()));
        let tt = ttOptional.unwrap_or(E::Fr::rand(rng));
        let mut a = E::Fqk::one();
        // TODO: consider optimizations to pairing in loop
        for j in 0..self.Y2.len() {
            if t.len() == j {
                t.push(E::Fr::rand(rng));
            }
            let mut gy = E::pairing(blindSig.h, self.Y2[j]);
            gy = gy.pow(t[j].into_repr());
            a.mul_assign(&gy);
        }
        let mut h = E::pairing(blindSig.h, mpk.g2);
        h = h.pow(tt.into_repr());
        a.mul_assign(&h);
        ProofState {
            v,
            t,
            tt,
            a,
            blindSig,
        }
    }

    /// prove knowledge of a signature: response phase
    /// returns a proof that can be send to the verifier together with the challenge and the blind signature
    pub fn prove_response(
        &self,
        ps: &ProofState<E>,
        challenge: E::Fr,
        message: &mut Vec<E::Fr>,
    ) -> SignatureProof<E> {
        let mut zsig = ps.t.clone();
        let z_len = zsig.len();

        for i in 0..message.len() {
            if i < z_len {
                let mut message1 = message[i];
                message1.mul_assign(&challenge);
                zsig[i].add_assign(&message1);
            }
        }

        let mut zv = ps.tt.clone();
        let mut vic = ps.v.clone();
        vic.mul_assign(&challenge);
        zv.add_assign(&vic);
        SignatureProof { zsig, zv, a: ps.a }
    }
}

pub fn setup<R: Rng, E: Engine>(csprng: &mut R) -> PublicParams<E> {
    let g1 = E::G1::rand(csprng);
    let g2 = E::G2::rand(csprng);
    let mpk = PublicParams { g1: g1, g2: g2 };
    return mpk;
}

///
/// KeyPair - implements the standard CL signature variant by PS - Section 3.1
///
impl<E: Engine> KeyPair<E> {
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, mpk, l);
        let public = PublicKey::from_secret(mpk, &secret);
        KeyPair { secret, public }
    }

    /// sign a vector of messages (of size l)
    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    pub fn verify(
        &self,
        mpk: &PublicParams<E>,
        message: &Vec<E::Fr>,
        signature: &Signature<E>,
    ) -> bool {
        self.public.verify(mpk, message, signature)
    }
}

///
/// BlindingKeyPair - implements the blinding signature scheme in PS - Section 3.1.1
///
impl<E: Engine> BlindKeyPair<E> {
    /// generate public/private keypair given public params and size of vectors
    pub fn generate<R: Rng>(csprng: &mut R, mpk: &PublicParams<E>, l: usize) -> Self {
        let secret = SecretKey::generate(csprng, mpk, l);
        let public = BlindPublicKey::from_secret(mpk, &secret);
        BlindKeyPair { secret, public }
    }

    pub fn generate_cs_multi_params(&self, mpk: &PublicParams<E>) -> CSMultiParams<E> {
        let mut com_bases = vec![mpk.g1];
        com_bases.append(&mut self.public.Y1.clone());

        CSMultiParams {
            pub_bases: com_bases,
        }
    }

    /// extract unblinded public key
    pub fn get_public_key(&self, mpk: &PublicParams<E>) -> PublicKey<E> {
        PublicKey::from_secret(mpk, &self.secret)
    }

    /// sign a vector of messages
    pub fn sign<R: Rng>(&self, csprng: &mut R, message: &Vec<E::Fr>) -> Signature<E> {
        self.secret.sign(csprng, message)
    }

    /// randomize signature
    pub fn rerandomize_signature<R: Rng>(
        &self,
        csprng: &mut R,
        signature: &Signature<E>,
    ) -> Signature<E> {
        let r = E::Fr::rand(csprng);
        let mut h = signature.h.clone();
        let mut H = signature.H.clone();
        h.mul_assign(r.clone());
        H.mul_assign(r);
        Signature { h, H }
    }

    /// sign a commitment of a vector of messages
    pub fn sign_blind<R: Rng>(
        &self,
        csprng: &mut R,
        mpk: &PublicParams<E>,
        com: Commitment<E>,
    ) -> Signature<E> {
        let u = E::Fr::rand(csprng);
        let mut h1 = mpk.g1;
        h1.mul_assign(u); // g1 ^ u

        let com1 = com.c.clone();
        let mut H1 = self.secret.X.clone();
        H1.add_assign(&com1); // (X * com)
        H1.mul_assign(u); // (X * com) ^ u (blinding factor)

        Signature { h: h1, H: H1 }
    }

    /// computes a blind signature from an existing one
    pub fn blind<R: Rng>(
        &self,
        csprng: &mut R,
        bf: &E::Fr,
        signature: &Signature<E>,
    ) -> Signature<E> {
        self.public.blind(csprng, bf, signature)
    }

    /// unblinds a signature given knowledge of blinding factor, t. Output should be
    /// verifiable with standard signature scheme.
    pub fn unblind(&self, bf: &E::Fr, signature: &Signature<E>) -> Signature<E> {
        self.public.unblind(bf, signature)
    }
}

// display CL signature (PS)
impl<E: Engine> fmt::Display for Signature<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signature : \n(h = {},\nH = {})", self.h, self.H)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Rand;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::{
        bls12_381::{G1Uncompressed, G2Uncompressed},
        EncodedPoint,
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::collections::HashMap;
    use util::convert_str_to_fr;

    #[test]
    fn sign_and_verify() {
        // let mut rng = XorShiftRng::seed_from_u64(0xbc4f6d44d62f276c);
        // let mut rng = XorShiftRng::seed_from_u64(0xb963afd05455863d);
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = KeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        println!("SECRET KEY => {}", keypair.secret);
        println!("PUBLIC KEY => {}", keypair.public);

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for _i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        println!("{}", sig);
        assert_eq!(keypair.verify(&mpk, &message1, &sig), true);
        assert_eq!(keypair.verify(&mpk, &message2, &sig), false);
    }

    #[test]
    fn blind_sign_and_verify() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let public_key = keypair.get_public_key(&mpk);

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for _i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        assert_eq!(public_key.verify(&mpk, &message1, &sig), true);
        assert_eq!(public_key.verify(&mpk, &message2, &sig), false);

        let t = Fr::rand(&mut rng);
        let blind_sig = keypair.blind(&mut rng, &t, &sig);

        // pick another blinding factor
        let t1 = Fr::rand(&mut rng);

        // verify blind signatures and provide blinding factor as input
        assert_eq!(
            keypair.public.verify_blind(&mpk, &message1, &t, &blind_sig),
            true
        );
        assert_eq!(
            keypair.public.verify_blind(&mpk, &message2, &t, &blind_sig),
            false
        );
        assert_eq!(
            keypair
                .public
                .verify_blind(&mpk, &message1, &t1, &blind_sig),
            false
        );

        let rand_sig = keypair.rerandomize_signature(&mut rng, &sig);
        assert_eq!(public_key.verify(&mpk, &message1, &rand_sig), true);
    }

    #[test]
    fn blind_unblind_works() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let mut message1: Vec<Fr> = Vec::new();

        for _i in 0..l {
            message1.push(Fr::rand(&mut rng));
        }

        let signature = keypair.sign(rng, &message1);
        let r = Fr::rand(rng);
        let blind_sig = keypair.blind(rng, &r, &signature);
        let signature1 = keypair.unblind(&r, &blind_sig);

        assert_eq!(
            keypair
                .get_public_key(&mpk)
                .verify(&mpk, &message1, &signature1),
            true
        );
        assert_eq!(
            keypair
                .get_public_key(&mpk)
                .verify(&mpk, &message1, &blind_sig),
            false
        );
        assert_eq!(
            keypair.public.verify_blind(&mpk, &message1, &r, &blind_sig),
            true
        );
    }

    #[test]
    fn blind_sign_and_verify_works() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let mut message1: Vec<Fr> = Vec::new();
        let mut message2: Vec<Fr> = Vec::new();

        for _i in 0..l {
            message1.push(Fr::rand(&mut rng));
            message2.push(Fr::rand(&mut rng));
        }

        let com_params = keypair.generate_cs_multi_params(&mpk);
        let t = Fr::rand(rng);
        let com = com_params.commit(&message1, &t);

        let signature = keypair.sign_blind(rng, &mpk, com);

        let unblinded_sig = keypair.unblind(&t, &signature);

        let t1 = Fr::rand(&mut rng);

        assert_eq!(
            keypair
                .get_public_key(&mpk)
                .verify(&mpk, &message1, &unblinded_sig),
            true
        );
        assert_eq!(
            keypair.public.verify_blind(&mpk, &message1, &t, &signature),
            true
        );
        assert_eq!(
            keypair
                .get_public_key(&mpk)
                .verify(&mpk, &message2, &unblinded_sig),
            false
        );
        assert_eq!(
            keypair.public.verify_blind(&mpk, &message2, &t, &signature),
            false
        );
        assert_eq!(
            keypair
                .public
                .verify_blind(&mpk, &message1, &t1, &signature),
            false
        );
    }

    #[test]
    fn proof_of_knowledge_of_signature() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let mut message1: Vec<Fr> = Vec::new();

        for _i in 0..l {
            message1.push(Fr::rand(&mut rng));
        }

        let sig = keypair.sign(&mut rng, &message1);
        let proof_state = keypair.public.prove_commitment(rng, &mpk, &sig, None, None);
        let challenge = proof_state.fs_challenge(&mpk);
        let proof = keypair
            .public
            .prove_response(&proof_state.clone(), challenge, &mut message1);

        // println!("{:?}", serde_json::to_string(&mpk).unwrap());
        // println!("{:?}", serde_json::to_string(&challenge).unwrap());
        // println!("{:?}", serde_json::to_string(&keypair).unwrap());
        // println!("{:?}", serde_json::to_string(&proof_state.blindSig).unwrap());
        // println!("{:?}", serde_json::to_string(&proof).unwrap());
        // println!("{:?}", proof.a.to_string());

        assert_eq!(
            keypair
                .public
                .verify_proof(&mpk, proof_state.blindSig, proof, challenge),
            true
        );
    }

    #[test]
    fn test_cl_basic_serialize() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let keypair = KeyPair::<Bls12>::generate(&mut rng, &mpk, l);
        let blindkeypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let serialized = serde_json::to_vec(&mpk).unwrap();
        println!("mpk serialized len = {:?}", serialized.len());

        let _mpk_des: PublicParams<Bls12> = serde_json::from_slice(&serialized).unwrap();
        //println!("{}", _mpk_des);

        //println!("SK => {}", &keypair.secret);
        let sk_serialized = serde_json::to_vec(&keypair.secret).unwrap();
        //println!("sk_serialized = {:?}", sk_serialized.len());

        let sk_des: SecretKey<Bls12> = serde_json::from_slice(&sk_serialized).unwrap();
        //println!("{}", sk_des);
        assert_eq!(sk_des, keypair.secret);

        //println!("PK => {}", &keypair.public);
        let pk_serialized = serde_json::to_vec(&keypair.public).unwrap();
        println!("cl pk_serialized len = {:?}", pk_serialized.len());

        let _pk_des: PublicKey<Bls12> = serde_json::from_slice(&pk_serialized).unwrap();
        //assert_eq!(pk_des, keypair.public);

        //println!("{}", &blindkeypair.public);
        let bpk_ser = serde_json::to_vec(&blindkeypair.public).unwrap();
        //println!("blind pk_ser = {:?}", bpk_ser.len());

        let bpk_des: BlindPublicKey<Bls12> = serde_json::from_slice(&bpk_ser).unwrap();
        assert_eq!(bpk_des, blindkeypair.public);

        let unblind_pk = blindkeypair.get_public_key(&mpk);
        //println!("{}", &unblind_pk);
        let upk_serialized = serde_json::to_vec(&unblind_pk).unwrap();
        //println!("upk_serialized = {:?}", upk_serialized.len());

        let upk_des: PublicKey<Bls12> = serde_json::from_slice(&upk_serialized).unwrap();

        assert_eq!(upk_des, unblind_pk);
        assert_ne!(upk_des, keypair.public);
    }

    #[test]
    fn test_compact_public_params_deserialize() {
        let bin_g1 = vec![
            132, 83, 99, 124, 75, 72, 15, 109, 12, 94, 84, 103, 1, 58, 160, 232, 190, 23, 119, 195,
            112, 161, 152, 141, 178, 29, 141, 61, 227, 246, 215, 157, 140, 190, 100, 18, 248, 141,
            57, 222, 12, 209, 191, 158, 143, 155, 87, 255,
        ];
        let bin_g2 = vec![
            147, 63, 33, 190, 248, 155, 91, 211, 249, 169, 1, 147, 101, 104, 219, 88, 204, 131, 38,
            167, 25, 191, 86, 67, 139, 188, 171, 101, 154, 32, 234, 92, 3, 66, 235, 159, 7, 47, 16,
            83, 3, 201, 13, 227, 179, 184, 101, 102, 21, 88, 153, 208, 93, 0, 57, 108, 250, 231,
            74, 192, 82, 111, 13, 211, 12, 51, 224, 198, 121, 15, 63, 129, 25, 218, 193, 47, 182,
            248, 112, 185, 163, 23, 175, 169, 76, 214, 36, 184, 142, 222, 48, 212, 157, 35, 115,
            181,
        ];

        let ser_g1 = util::encode_as_hexstring(&bin_g1);
        let ser_g2 = util::encode_as_hexstring(&bin_g2);

        let str_g1 = ser_g1.as_bytes();
        let str_g2 = ser_g2.as_bytes();

        let rec_mpk = PublicParams::<Bls12>::from_slice(&str_g1, &str_g2);

        println!("g1: {}", rec_mpk.g1);
        println!("g2: {}", rec_mpk.g2);

        let rec_g1_str = serde_json::to_string(&rec_mpk.g1).unwrap();
        assert_eq!(rec_g1_str, "\"8453637c4b480f6d0c5e5467013aa0e8be1777c370a1988db21d8d3de3f6d79d8cbe6412f88d39de0cd1bf9e8f9b57ff\"");

        let rec_g2_str = serde_json::to_string(&rec_mpk.g2).unwrap();
        assert_eq!(rec_g2_str, "\"933f21bef89b5bd3f9a901936568db58cc8326a719bf56438bbcab659a20ea5c0342eb9f072f105303c90de3b3b86566155899d05d00396cfae74ac0526f0dd30c33e0c6790f3f8119dac12fb6f870b9a317afa94cd624b88ede30d49d2373b5\"");
    }

    #[test]
    fn test_compact_cl_public_key_deserialize() {
        let bin_g2_x = vec![
            147, 63, 33, 190, 248, 155, 91, 211, 249, 169, 1, 147, 101, 104, 219, 88, 204, 131, 38,
            167, 25, 191, 86, 67, 139, 188, 171, 101, 154, 32, 234, 92, 3, 66, 235, 159, 7, 47, 16,
            83, 3, 201, 13, 227, 179, 184, 101, 102, 21, 88, 153, 208, 93, 0, 57, 108, 250, 231,
            74, 192, 82, 111, 13, 211, 12, 51, 224, 198, 121, 15, 63, 129, 25, 218, 193, 47, 182,
            248, 112, 185, 163, 23, 175, 169, 76, 214, 36, 184, 142, 222, 48, 212, 157, 35, 115,
            181,
        ];
        let bin_g2_y1 = vec![
            143, 76, 112, 7, 35, 99, 254, 7, 255, 225, 69, 13, 99, 32, 92, 186, 234, 175, 230, 0,
            202, 144, 1, 216, 187, 248, 152, 76, 229, 74, 156, 94, 4, 16, 132, 119, 157, 172, 231,
            164, 207, 88, 41, 6, 234, 78, 73, 58, 19, 104, 236, 127, 5, 231, 248, 150, 53, 197, 85,
            194, 110, 93, 1, 73, 24, 96, 149, 133, 109, 194, 16, 190, 244, 184, 254, 192, 52, 21,
            205, 109, 18, 83, 189, 175, 208, 147, 74, 32, 181, 126, 224, 136, 250, 126, 224, 186,
        ];
        let bin_g2_y2 = vec![
            150, 132, 45, 236, 146, 135, 127, 242, 61, 55, 73, 100, 151, 12, 51, 134, 151, 42, 138,
            227, 105, 54, 121, 7, 0, 27, 205, 139, 186, 69, 139, 143, 41, 132, 35, 33, 168, 35, 31,
            52, 65, 5, 73, 153, 203, 25, 178, 196, 4, 9, 218, 130, 22, 64, 98, 152, 225, 212, 27,
            202, 245, 234, 138, 34, 82, 102, 40, 72, 211, 248, 16, 221, 54, 154, 186, 95, 246, 132,
            54, 0, 128, 170, 111, 94, 155, 166, 27, 225, 51, 31, 107, 223, 139, 0, 209, 236,
        ];

        let ser_g2_x = util::encode_as_hexstring(&bin_g2_x);
        let ser_g2_y1 = util::encode_as_hexstring(&bin_g2_y1);
        let ser_g2_y2 = util::encode_as_hexstring(&bin_g2_y2);

        let str_g2_x = ser_g2_x.as_bytes();
        let str_g2_y1 = ser_g2_y1.as_bytes();
        let str_g2_y2 = ser_g2_y2.as_bytes();

        let mut vec = Vec::new();
        vec.extend(str_g2_y1);
        vec.extend(str_g2_y2);

        let rec_cl_pk =
            PublicKey::<Bls12>::from_slice(&str_g2_x, &vec.as_slice(), ser_g2_y1.len(), 2);

        let rec_x_str = serde_json::to_string(&rec_cl_pk.X).unwrap();
        assert_eq!(rec_x_str, "\"933f21bef89b5bd3f9a901936568db58cc8326a719bf56438bbcab659a20ea5c0342eb9f072f105303c90de3b3b86566155899d05d00396cfae74ac0526f0dd30c33e0c6790f3f8119dac12fb6f870b9a317afa94cd624b88ede30d49d2373b5\"");

        let rec_y1_str = serde_json::to_string(&rec_cl_pk.Y[0]).unwrap();
        assert_eq!(rec_y1_str, "\"8f4c70072363fe07ffe1450d63205cbaeaafe600ca9001d8bbf8984ce54a9c5e041084779dace7a4cf582906ea4e493a1368ec7f05e7f89635c555c26e5d0149186095856dc210bef4b8fec03415cd6d1253bdafd0934a20b57ee088fa7ee0ba\"");

        let rec_y2_str = serde_json::to_string(&rec_cl_pk.Y[1]).unwrap();
        assert_eq!(rec_y2_str, "\"96842dec92877ff23d374964970c3386972a8ae369367907001bcd8bba458b8f29842321a8231f3441054999cb19b2c40409da8216406298e1d41bcaf5ea8a2252662848d3f810dd369aba5ff684360080aa6f5e9ba61be1331f6bdf8b00d1ec\"");
    }

    #[test]
    fn test_cl_basic_test() {
        // let mut rng = &mut rand::thread_rng();
        let mut rng = XorShiftRng::seed_from_u64(0x5dbe62598d313d76);

        let l = 5;
        let m_len = 4;
        let mpk = setup(&mut rng);
        // println!("mpk.g2 = {}", serde_json::to_string(&mpk.g2).unwrap());
        let keypair = KeyPair::<Bls12>::generate(&mut rng, &mpk, l);

        let pubkey = keypair.public.clone();
        // println!("PK: {}", serde_json::to_string(&pubkey).unwrap());

        let mut message: Vec<Fr> = Vec::new();
        message.push(
            convert_str_to_fr::<Bls12>(
                // Fr(0x37cdad6e6ec1e1a1f5498dd078eaf727b6f5956ef5b8472bf381f0703583a667)
                String::from(
                    "25240607299735458558322812412766230124357940997338768540956287062183476700775",
                ),
            )
            .unwrap(),
        );
        // Fr(0x290e213d8593f05dffcb8075f295224ad426bcdcef4bee5c3e2499c41ea898c4)
        message.push(
            convert_str_to_fr::<Bls12>(String::from(
                "18569792067074403428287286662712990656991493160983975159578971686520014543044",
            ))
            .unwrap(),
        );

        for _i in 2..m_len {
            message.push(Fr::rand(&mut rng));
        }
        println!("<= Message =>");
        println!("m0: {}", serde_json::to_string(&message[0]).unwrap());
        println!("m1: {}", serde_json::to_string(&message[1]).unwrap());
        println!("m2: {}", serde_json::to_string(&message[2]).unwrap());
        println!("m3: {}", serde_json::to_string(&message[3]).unwrap());

        let signature = keypair.sign(&mut rng, &message);
        // println!("SIG: {}", serde_json::to_string(&signature).unwrap());
        let (res, pp) = pubkey.debug_verify(&mpk, &message, &signature);
        assert_eq!(res, true);

        // output
        let mut merch_pk_map = HashMap::new();
        let mut y_partial_prod_map = HashMap::new();
        let mut l_partial_prod_map = HashMap::new();
        let mut signature_map = HashMap::new();

        // encode the merch public key
        let g2 = G2Uncompressed::from_affine(mpk.g2.into_affine());
        let x2 = G2Uncompressed::from_affine(pubkey.X.into_affine());

        // encode the signature
        let s1 = G1Uncompressed::from_affine(signature.h.into_affine());
        let s2 = G1Uncompressed::from_affine(signature.H.into_affine());

        merch_pk_map.insert("g2".to_string(), hex::encode(&g2));
        merch_pk_map.insert("X".to_string(), hex::encode(&x2));
        let l = pubkey.Y.len();
        for i in 0..l {
            let key = format!("Y{}", i);
            let y = G2Uncompressed::from_affine(pubkey.Y[i].into_affine());
            merch_pk_map.insert(key, hex::encode(&y));
        }

        for i in 0..pp.Ys.len() {
            let key = format!("Ys{}", i);
            let y = G2Uncompressed::from_affine(pp.Ys[i].into_affine());
            y_partial_prod_map.insert(key, hex::encode(&y));
        }

        for i in 0..pp.Ls.len() {
            let key = format!("Ls{}", i);
            let y = G2Uncompressed::from_affine(pp.Ls[i].into_affine());
            l_partial_prod_map.insert(key, hex::encode(&y));
        }

        signature_map.insert("s1".to_string(), hex::encode(&s1));
        signature_map.insert("s2".to_string(), hex::encode(&s2));

        println!("=========================");
        println!(
            "merch_pk: {}",
            serde_json::to_string(&merch_pk_map).unwrap()
        );
        println!(
            "signature: {}",
            serde_json::to_string(&signature_map).unwrap()
        );
        println!("=========================");
        println!(
            "partial results for Y_i * m_i: {}",
            serde_json::to_string(&y_partial_prod_map).unwrap()
        );
        println!(
            "partial results for L += (Y_i * m_i): {}",
            serde_json::to_string(&l_partial_prod_map).unwrap()
        );
    }
}
