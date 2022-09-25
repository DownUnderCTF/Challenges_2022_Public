Run the code here: https://aussieplusplus.vercel.app

You can choose to reverse it and then append:

``GIMME i_should_print_the_flag`` 

to the end of the code to print the flag. 

 ( Check ducft-aussieplusplus.txt file for an example right at the bottom )

You can skip the reverse stage and just add:

``;ƃɐlɟ_ǝɥʇ_ʇuᴉɹd_plnoɥs_ᴉ ƎWWIפ` ``

To right after the ` ¡***Ɔ SɹƎƎHƆ ` for an even faster solve.


90% of the challenge is in figuring out what Aussie++ is, as a fun meme

``OUTPUT: irkugvcgppdjbruwknjw5yuiqbp4tok7nzpxhruwzgs4vb27itriraggsde3sx2o4ockhrugl7rirkjq4kcyix7cqszes7i=``

There are a couple of referneces to a flag cabinet pin that include it being loweracse and 64 / 2 which should hopefully hint at it
being a non-standard base32 decode.

Throuw it into a base34 decoder with a-z2-7 and you have:

``FLAG: DUCTF{ƐƖSSn∀_ɹ_n_sƖɥʇ_D∀Ɛɹ_NㄣƆ_∩0⅄_ℲI}``

