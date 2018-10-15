---
title: "SHA2017 - Stolen Bitcoins (300pt)"
description: "Reverse engineer bitcoin script"
date: 2017-08-06
tags: ["reverse"]
---

# Stolen Bitcoins (300pt)

**`Reverse`**

**Description:** Someone stole our Bitcoins, luckily we captured the transaction. Can you find the flag that will allow us to get them back?

**Files:**

* [stolenbitcoins.tgz](/code/2017/SHA2017/stolen-bitcoins/stolenbitcoins.tgz)
* Decoded script for convenience: [script.txt](/code/2017/SHA2017/stolen-bitcoins/script.txt)

# Solution

Opening the archive reveals a transmission file with some encoded data:

```
01000000000100e40b5402000000f...
```

Since the description says this is a Bitcoin transaction, I tried decoding it with [Chain Query](https://chainquery.com/bitcoin-api/decoderawtransaction) which revealed the following information:

```json
{
	"result": {
		"txid": "3997ec296bdc4d7c521369c64d84ebb170cf9263ebc40d2b568e22059b02f0f5",
		"hash": "3997ec296bdc4d7c521369c64d84ebb170cf9263ebc40d2b568e22059b02f0f5",
		"size": 672,
		"vsize": 672,
		"version": 1,
		"locktime": 0,
		"vin": [

		],
		"vout": [
			{
				"value": 100.00000000,
				"n": 0,
				"scriptPubKey": {
					"asm": "0 10 OP_PICK 23 OP_PICK OP_ADD 99 OP_EQUAL OP_ADD 33 OP_PICK 21 OP_PICK OP_ADD 198 OP_EQUAL OP_ADD 37 OP_PICK 98 OP_ADD 206 OP_EQUAL OP_ADD 29 OP_PICK 25 OP_PICK OP_ADD 104 OP_EQUAL OP_ADD 26 OP_PICK 29 OP_PICK OP_ADD 148 OP_EQUAL OP_ADD 6 OP_PICK 3 OP_PICK OP_ADD 157 OP_EQUAL OP_ADD 30 OP_PICK OP_RIPEMD160 412fc6097e62d5c494b8df37e3805805467d1a2c OP_EQUAL OP_ADD 13 OP_PICK 11 OP_PICK OP_ADD 105 OP_EQUAL OP_ADD 32 OP_PICK 34 OP_PICK OP_ADD 155 OP_EQUAL OP_ADD 1 OP_PICK 113 OP_ADD 238 OP_EQUAL OP_ADD 18 OP_PICK 32 OP_PICK OP_ADD 149 OP_EQUAL OP_ADD 5 OP_PICK 3 OP_PICK OP_ADD 157 OP_EQUAL OP_ADD 2 OP_PICK 4 OP_PICK OP_ADD 112 OP_EQUAL OP_ADD 9 OP_PICK 34 OP_PICK OP_ADD 158 OP_EQUAL OP_ADD 25 OP_PICK 30 OP_PICK OP_ADD 149 OP_EQUAL OP_ADD 4 OP_PICK 11 OP_PICK OP_ADD 148 OP_EQUAL OP_ADD 21 OP_PICK 17 OP_PICK OP_ADD 111 OP_EQUAL OP_ADD 36 OP_PICK 22 OP_ADD 119 OP_EQUAL OP_ADD 27 OP_PICK 17 OP_PICK OP_ADD 106 OP_EQUAL OP_ADD 22 OP_PICK 17 OP_PICK OP_ADD 105 OP_EQUAL OP_ADD 35 OP_PICK 12 OP_ADD 115 OP_EQUAL OP_ADD 38 OP_PICK 111 OP_ADD 213 OP_EQUAL OP_ADD 8 OP_PICK 23 OP_PICK OP_ADD 106 OP_EQUAL OP_ADD 31 OP_PICK 7 OP_PICK OP_ADD 151 OP_EQUAL OP_ADD 12 OP_PICK 28 OP_PICK OP_ADD 148 OP_EQUAL OP_ADD 34 OP_PICK 53 OP_ADD 176 OP_EQUAL OP_ADD 28 OP_PICK 22 OP_PICK OP_ADD 106 OP_EQUAL OP_ADD 19 OP_PICK 4 OP_PICK OP_ADD 108 OP_EQUAL OP_ADD 23 OP_PICK OP_RIPEMD160 c47907abd2a80492ca9388b05c0e382518ff3960 OP_EQUAL OP_ADD 15 OP_PICK 18 OP_PICK OP_ADD 155 OP_EQUAL OP_ADD 11 OP_PICK OP_RIPEMD160 8e95e8ccac6c8eb91b8a7a8f02bca2fa2268d4b2 OP_EQUAL OP_ADD 16 OP_PICK 21 OP_PICK OP_ADD 152 OP_EQUAL OP_ADD 3 OP_PICK 34 OP_PICK OP_ADD 156 OP_EQUAL OP_ADD 17 OP_PICK 3 OP_PICK OP_ADD 157 OP_EQUAL OP_ADD 24 OP_PICK 20 OP_PICK OP_ADD 106 OP_EQUAL OP_ADD 7 OP_PICK OP_RIPEMD160 38f77e12c50a398d5eae85c9408667f971d09d09 OP_EQUAL OP_ADD 14 OP_PICK 29 OP_PICK OP_ADD 107 OP_EQUAL OP_ADD 20 OP_PICK 23 OP_PICK OP_ADD 147 OP_EQUAL OP_ADD OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP OP_NIP 38 OP_EQUAL",
					"hex": "4c01004c010a794c011779934c016387934c0121794c011579934c02c60087934c0125794c0162934c02ce0087934c011d794c011979934c016887934c011a794c011d79934c02940087934c0106794c010379934c029d0087934c011e79a64c14412fc6097e62d5c494b8df37e3805805467d1a2c87934c010d794c010b79934c016987934c0120794c012279934c029b0087934c0101794c0171934c02ee0087934c0112794c012079934c02950087934c0105794c010379934c029d0087934c0102794c010479934c017087934c0109794c012279934c029e0087934c0119794c011e79934c02950087934c0104794c010b79934c02940087934c0115794c011179934c016f87934c0124794c0116934c017787934c011b794c011179934c016a87934c0116794c011179934c016987934c0123794c010c934c017387934c0126794c016f934c02d50087934c0108794c011779934c016a87934c011f794c010779934c02970087934c010c794c011c79934c02940087934c0122794c0135934c02b00087934c011c794c011679934c016a87934c0113794c010479934c016c87934c011779a64c14c47907abd2a80492ca9388b05c0e382518ff396087934c010f794c011279934c029b0087934c010b79a64c148e95e8ccac6c8eb91b8a7a8f02bca2fa2268d4b287934c0110794c011579934c02980087934c0103794c012279934c029c0087934c0111794c010379934c029d0087934c0118794c011479934c016a87934c010779a64c1438f77e12c50a398d5eae85c9408667f971d09d0987934c010e794c011d79934c016b87934c0114794c011779934c029300879377777777777777777777777777777777777777777777777777777777777777777777777777774c012687",
					"type": "nonstandard"
				}
			}
		]
	},
	"error": null,
	"id": null
}
```

Here we can see that it is a transaction to pay **a lot** of bitcoins to a single utxo with a suspiciously long script.

For those who are unfamiliar: when you *send* bitcoins to someone, you don't actually send it to their account or address. Instead, you provide a script (also known as a "locking script" or "scriptPubKey") written in Bitcoin's appropriatly named scripting language: [Script](https://en.bitcoin.it/wiki/Script).

In order for someone to later spend this utxo, they must be able to validate the script. Essentially, this means they will provide another script (the "unlocking script" or "scriptSig") that is concatenated before the locking script. If the entire program runs without failure and terminates with a non-zero value at the top of the stack, the transaction is valid.

Normally, people will use one of a few common scripts such as Pay-to-Public-Key-Hash (P2PKH) or Pay-to-Multisig (P2MS) which have the same effect as actually sending bitcoins to an address. However, this is not a requirement.

# The Script

While the script looks very intimidating at first glance, it can be broken down and understood.

We start with a single zero that just pushes the value zero onto the stack:

```py
0
```

Then the following type of pattern repeats:

```py
10 OP_PICK 
23 OP_PICK 
OP_ADD 
99 
OP_EQUAL 
OP_ADD
```

Let's break it down and see what it does. I'll go opcode by opcode and keep track of the stack. First, we have a stack containing some previous values (that we have to figure out) followed by that zero:

*(I'm drawing a stack that grows upwards)*

```
--- << base
0
val_1
val_2
val_3
...
val_n
```

The `OP_PICK` code pops `n` off the top of the stack and then copies the value `n` bytes back to the top of the stack. So after performing:

```py
10 OP_PICK
```

the stack looks like:

```
val_10
--- << base
0
val_1
val_2
val_3
...
val_n
```

Then we perform another `OP_PICK`, however since the stack has grown by one, we are actually selecting the `n-1`th value. (This tripped me up for a while). So our stack now looks like this:

```
val_22
val_10
--- << base
0
val_1
val_2
val_3
...
val_n
```

Next, we perform a `OP_ADD` which simply pops two values off the stack, adds them, then pushes the sum back on:

```
val_10 + val_22
--- << base
0
val_1
val_2
val_3
...
val_n
```

Then we push a constant onto the stack: `99`.

```
99
val_10 + val_22
--- << base
0
val_1
val_2
val_3
...
val_n
```

Next, we perform an `OP_EQUAL` which pops two values off the stack and checks if they are equal. If they are, a `1` is pushed onto the stack. Otherwise, a `0` is pushed on.

```
(val_10 + val_22 == 99 ? 1 : 0)
--- << base
0
val_1
val_2
val_3
...
val_n
```

Finally, an `OP_ADD` takes this `1` or `0` value and adds it to the zero from earlier.

In this way, the stack pointer has been reset to the original position for the next block:

```py
33 OP_PICK 
21 OP_PICK 
OP_ADD 
198 
OP_EQUAL 
OP_ADD
```

Now, what conditions have to be met in order to validate the transaction? Well, after a whole bunch of these code sections, we see the following:

```py
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP OP_NIP OP_NIP 
OP_NIP OP_NIP 

38 
OP_EQUAL
```

The `OP_NIP` operation removes the second value from the top of the stack. So as we go operation by operation, the values from before are removed and we are left with just the sum value:

```
--- << base
sum
```

Then we push `38` and check for equality. Now in order for the transaction to be valid, the script must end with a non-zero value at the top of the stack. So our sum must be equal to `38`. Since there are exactly 38 code sections, all of the equality checks must be true.

Essentially this leaves us with a bunch of equations we have to satisfy to determine the flag.

# Other section types:

There are two other types of sections that maintain the stack frame:

#### Adding with a constant

```py
1 OP_PICK 
113 
OP_ADD 
238 
OP_EQUAL 
OP_ADD 
```

In this case, we check if `val_1 + 113 == 238`. Since this must be true, we can determine that `val_1` is equal to `125` or `'}'`. Since flags are of the format `flag{md5}` we can deduce that the flag is stored backwards from the top of the stack like so:

```
}
val_2
val_3
...
val_33
{
g
a
l
f
```

#### Hash Check

The third block type is a hash comparison such as:

```py
30 OP_PICK 
OP_RIPEMD160 
412fc6097e62d5c494b8df37e3805805467d1a2c 
OP_EQUAL 
OP_ADD 
```

This is checking whether `ripemd160(val_30) == '412fc6097e62d5c494b8df37e3805805467d1a2c'`. Since we know that `val_30` is a single ascii character, we only have to brute force a space of `2^7` which can be done like so:

```py
import hashlib

def find(hash_string):
    for i in range(32,128):
        c = chr(i)
        h = hashlib.new('ripemd160')
        h.update(c)

        if h.hexdigest() == hash_string:
            return c

    return ''
```

```py
>>> find('412fc6097e62d5c494b8df37e3805805467d1a2c')
'2'
```

# The Boring Part

Now, we have a series of equations and all that's left to do is find a flag such that all the equations are true. Unfortunately, after you go through and fill in all the constant ones, none of the other characters are forced to any value.

*Example equations below (left side is character index, right side is raw value)*

```py
10 + 22 = 99
13 + 10 = 105
4 + 10 = 148
33 + 20 = 198
29 + 24 = 104
26 + 28 = 148
6 + 2 = 157
5 + 2 = 157
...
```

It felt kind of like a less exciting sudoku puzzle.

In fact, I found two distinct sets of characters that had no equations comparing them to the other set.

After I had gone through all the equations, I actually had three flags that appeared to pass all the checks:

```
flag{e612123bd7128a3df7598a6198fffc97}
flag{e622223bc6128a4ce7698a6198feec88}
flag{e632323bb5128a5bd7798a6198fddc79}
```

*Note: I'm not sure if I made a mistake here or if there was a slight logic error in the problem creation*

As the saying goes, "the third flag's the charm," or something like that.