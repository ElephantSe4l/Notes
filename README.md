# Notes
> This repository contains all the notes I wrote during my research. Many things may not be accurate or even wrong. These are simply my attempts to understand how things work.

### Section Creation
After reading some posts about how Windows creates image sections, I wanted to investigate how it works. It is an interesting topic that can benefit in a lot of offensive security scenarios. See for example [Process Herpaderping](https://jxy-s.github.io/herpaderping/res/DivingDeeper.html) or [this post](https://www.fortinet.com/blog/threat-research/windows-pssetloadimagenotifyroutine-callbacks-the-good-the-bad).

For this reason I have been trying to understand the (basic) flow of this mechanism and reverse engineer it into an easy-to-read code. Within `WindowsSectionCreation.cpp` there is pseudocode that mimics the functionality of `MiCreateImageOrDataSection` in a basic way. I will probably continue with the rest of the functions at some point.

