pragma solidity ^0.4.18;

import "./Secp256k1.sol";

library Utils {
    uint constant pp = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // Order of G
    uint constant nn = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    // Parameters xG, r where r = v - xc, and vG.
    // Verify that vG = rG + xcG!
    function verifyZKP(uint[2] xG, uint r, uint[3] vG) returns (bool){
      uint[2] memory G;
      G[0] = Gx;
      G[1] = Gy;

      // Check both keys are on the curve.
      if(!Secp256k1.isPubKey(xG) || !Secp256k1.isPubKey(vG)) {
        return false; //Must be on the curve!
      }

      // Get c = H(g, g^{x}, g^{v});
      bytes32 b_c = sha256(msg.sender, Gx, Gy, xG, vG);
      uint c = uint(b_c);

      // Get g^{r}, and g^{xc}
      uint[3] memory rG = Secp256k1._mul(r, G);
      uint[3] memory xcG = Secp256k1._mul(c, xG);

      // Add both points together
      uint[3] memory rGxcG = Secp256k1._add(rG,xcG);

      // Convert to Affine Co-ordinates
      ECCMath.toZ1(rGxcG, pp);

      // Verify. Do they match?
      if(rGxcG[0] == vG[0] && rGxcG[1] == vG[1]) {
         return true;
      } else {
         return false;
      }
    }

  // We verify that the ZKP is of 0 or 1.
  function verify1outof2ZKP(uint[4] params, uint[2] xG, uint[2] yG, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
      uint[2] memory G;
      G[0] = Gx;
      G[1] = Gy;
      uint[2] memory temp1;
      uint[3] memory temp2;
      uint[3] memory temp3;

      // Make sure we are only dealing with valid public keys!
      if(!Secp256k1.isPubKey(xG) || !Secp256k1.isPubKey(yG) || !Secp256k1.isPubKey(y) || !Secp256k1.isPubKey(a1) ||
         !Secp256k1.isPubKey(b1) || !Secp256k1.isPubKey(a2) || !Secp256k1.isPubKey(b2)) {
         return false;
      }

      // Does c =? d1 + d2 (mod n)
      if(uint(sha256(msg.sender, xG, y, a1, b1, a2, b2)) != addmod(params[0],params[1],nn)) {
        return false;
      }

      // a1 =? g^{r1} * x^{d1}
      temp2 = Secp256k1._mul(params[2], G);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[0], xG));
      ECCMath.toZ1(temp3, pp);

      if(a1[0] != temp3[0] || a1[1] != temp3[1]) {
        return false;
      }

      //b1 =? h^{r1} * y^{d1} (temp = affine 'y')
      temp2 = Secp256k1._mul(params[2],yG);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[0], y));
      ECCMath.toZ1(temp3, pp);

      if(b1[0] != temp3[0] || b1[1] != temp3[1]) {
        return false;
      }

      //a2 =? g^{r2} * x^{d2}
      temp2 = Secp256k1._mul(params[3],G);
      temp3 = Secp256k1._add(temp2, Secp256k1._mul(params[1], xG));
      ECCMath.toZ1(temp3, pp);

      if(a2[0] != temp3[0] || a2[1] != temp3[1]) {
        return false;
      }

      // Negate the 'y' co-ordinate of g
      temp1[0] = G[0];
      temp1[1] = pp - G[1];

      // get 'y'
      temp3[0] = y[0];
      temp3[1] = y[1];
      temp3[2] = 1;

      // y-g
      temp2 = Secp256k1._addMixed(temp3,temp1);

      // Return to affine co-ordinates
      ECCMath.toZ1(temp2, pp);
      temp1[0] = temp2[0];
      temp1[1] = temp2[1];

      // (y-g)^{d2}
      temp2 = Secp256k1._mul(params[1],temp1);

      // Now... it is h^{r2} + temp2..
      temp3 = Secp256k1._add(Secp256k1._mul(params[3],yG),temp2);

      // Convert to Affine Co-ordinates
      ECCMath.toZ1(temp3, pp);

      // Should all match up.
      if(b2[0] != temp3[0] || b2[1] != temp3[1]) {
        return false;
      }

      return true;
    }
}
