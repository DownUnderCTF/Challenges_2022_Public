Clicky
============

Quick overview of the code, the box size goes from 100, to 75, to 10 while increasing speed. The obvious way to solve is to use a .NET reversing tool (https://www.jetbrains.com/decompiler/) and to start picking through the code though an alternate is to program a clicker, slow the application or similar. Would be great to see these write-ups posted!

The other .NET reverse challenge used string building code with base64 to obfuscate (though not very well) how the flag was created. This time around it also used the label control text that's outside the viewable area, so you'll need to also find and pay attention to all of the controls within the application.

It should be somewhat straight forward, just with a bit more noise than the other .NET rev, hope you enjoyed and learnt a bit about .NET reversing.
