https://cryptopals.com/

Working through these in Golang. Learning the language as I re-learn (or learn in a different way) cryptographic/number theory stuff I kind of did already in university (UPDATE 2 weeks later: actually, in university the cryptography I learnt definitely made more sense than most of these challenges).

#### USAGE: 

  Use command-line to specify set #, challenge # and any string arguments 
  e.g for set 1, challenge 1: 
  ```
    ./main 1 1 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
  ```
  My count restarts at the beginning of every set (sunk-cost). Challenge-specific file inputs don't need to be specified on the command-line. Have a gander at set%d_data for the given set %d to see which challenges have file inputs.

Skipped challenge 15/2.6 because it was just an annoying variation on the already extremely silly challenge 2.4. Hating set 2.

... Luckily, Set 3 is good again.

##### Update on June 9 2020:
Took a long break, and when I returned, I decided to skip basically the entire second half of Set 3 for reasons I go into in a long comment in *set3.go*. The short version is: a combination of the fact that the challenges themselves are clearly lazy and my getting a little lazier personally. Honestly, though, there is absolutely no reason for me to implement my own version of the Mersenne Twister RNG - it seems to be the mathematical equivalent of a whirpool (I don't want to know about any algorithm with that many constants)... And it has been implemented uncountably many times before.

On another topic, I continue to be surprised by how poorly written these challenges are, given their popularity and continued use. Why don't they get updated for clarity? I almost feel like some of the time the ambiguity is there to hide the fact that the challenge itself is lame/stupid.
