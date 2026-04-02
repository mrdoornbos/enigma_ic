; ==============================
; enigma ic attack
; index of coincidence search
; commodore 64
; rotors i-viii (m3), no plugboard
; turbo macro pro / tmpx
; by michael doornbos 2026
; mike@imapenguin.com
;
; decrypts ciphertext with each
; candidate setting, computes ic
; of the result, flags candidates
; with ic above threshold
;
; no crib needed
;
; .null/.text = screen codes
; use .byte for petscii strings
; ==============================

* = $c000

; --- zero page ---
ptr       = $50
rightpos = $fb
midpos   = $fc
leftpos  = $fd
temp      = $fe

chrout    = $ffd2

; === entry point ===
          ; zero jiffy clock and accumulator
          lda #0
          sta $a2
          sta $a1
          sta $a0
          sta jtotal
          sta jtotal+1
          sta jtotal+2
          sta jtotal+3

          ; cls, white text
          lda #$93
          jsr chrout
          lda #5
          jsr chrout
          lda #13
          jsr chrout

          ; header
          ldx #<stitle
          ldy #>stitle
          jsr print
          lda #13
          jsr chrout
          ldx #<ssub
          ldy #>ssub
          jsr print
          lda #13
          jsr chrout
          lda #13
          jsr chrout

          ; searching message
          ldx #<ssearch
          ldy #>ssearch
          jsr print
          lda #13
          jsr chrout

          ; init candidate count
          lda #0
          sta candlo
          sta candhi

          ; run search
          jsr searchall

          ; restore border
          lda #14
          sta $d020

          ; show total
          lda #13
          jsr chrout
          lda #13
          jsr chrout
          ldx #<stotal
          ldy #>stotal
          jsr print
          lda candhi
          ldx candlo
          jsr $bdcd
          ldx #<scands
          ldy #>scands
          jsr print
          lda #13
          jsr chrout

          ; show elapsed time
          ldx #<stime
          ldy #>stime
          jsr print
          jsr jiffysec
          lda #13
          jsr chrout
          rts

; === search all orderings ===
; p(8,3) = 336 permutations
searchall
          lda #0
          sta tryl
saleft   lda #0
          sta trym
samid    lda trym
          cmp tryl
          beq sasm
          lda #0
          sta tryr
saright  lda tryr
          cmp tryl
          beq sasr
          cmp trym
          beq sasr
          ; valid permutation
          jsr searchpos
sasr     inc tryr
          lda tryr
          cmp #8
          bne saright
sasm     inc trym
          lda trym
          cmp #8
          bne samid
          inc tryl
          lda tryl
          cmp #8
          bne saleft
sadone   rts

; === search positions ===
; 26^3 = 17,576 per ordering
searchpos
          ; check if jiffy clock wrapped
          ; accumulate jiffy clock, then zero it
          ; prevents kernal midnight reset (24h)
          sei
          clc
          lda jtotal
          adc $a2
          sta jtotal
          lda jtotal+1
          adc $a1
          sta jtotal+1
          lda jtotal+2
          adc $a0
          sta jtotal+2
          bcc jnoc
          inc jtotal+3
jnoc      lda #0
          sta $a2
          sta $a1
          sta $a0
          cli
          ; configure rotors
          lda tryl
          sta leftsel
          lda trym
          sta midsel
          lda tryr
          sta rightsel
          ; border color = progress
          inc $d020
          ; sweep all positions
          lda #0
          sta trylp
splp     lda #0
          sta trymp
spmp     lda #0
          sta tryrp
sprp
          ; test ic
          jsr testic
          beq tifound
          ; failed
          jmp tinext
tifound
          ; show candidate
          jsr showcand
tinext   inc tryrp
          lda tryrp
          cmp #26
          bne sprp
          inc trymp
          lda trymp
          cmp #26
          bne spmp
          inc trylp
          lda trylp
          cmp #26
          bne splp
          rts

; === test ic ===
; decrypts ciphertext
; computes ic sum
; returns z flag set if >= threshold
testic
          ; clear frequency table
          ldx #25
          lda #0
ticlr    sta freq,x
          dex
          bpl ticlr

          ; set starting positions
          lda trylp
          sta leftpos
          lda trymp
          sta midpos
          lda tryrp
          sta rightpos

          ; decrypt all 60 chars
          ldx #0
tidec    lda cipher,x
          stx savex
          jsr encrypt
          ; count frequency
          tax
          inc freq,x
          ldx savex
          inx
          cpx #60
          bne tidec

          ; compute ic sum (16-bit)
          lda #0
          sta iclo
          sta ichi
          ldx #0
tisum    lda freq,x
          beq tiskp
          cmp #1
          beq tiskp
          ; a = n, compute n*(n-1)
          tay
          dey
          sty temp
          iny
          lda #0
          clc
timul    adc temp
          dey
          bne timul
          ; add to 16-bit sum
          clc
          adc iclo
          sta iclo
          bcc tiskp
          inc ichi
tiskp    inx
          cpx #26
          bne tisum

          ; compare to threshold 194
          lda ichi
          bne tiyes
          lda iclo
          cmp #194
          bcs tiyes
          ; below threshold
          lda #1
          rts
tiyes    lda #0
          rts

; === show candidate ===
showcand
          ; increment count
          inc candlo
          bne scnoc
          inc candhi
scnoc
          lda #13
          jsr chrout
          ; print ordering
          ldx leftsel
          jsr printrn
          lda #45
          jsr chrout
          ldx midsel
          jsr printrn
          lda #45
          jsr chrout
          ldx rightsel
          jsr printrn
          lda #32
          jsr chrout
          ; print position
          lda trylp
          clc
          adc #65
          jsr chrout
          lda #45
          jsr chrout
          lda trymp
          clc
          adc #65
          jsr chrout
          lda #45
          jsr chrout
          lda tryrp
          clc
          adc #65
          jsr chrout
          lda #32
          jsr chrout
          ; print ic sum
          lda ichi
          ldx iclo
          jsr $bdcd
          lda #32
          jsr chrout
          ; decrypt first 40 chars
          lda trylp
          sta leftpos
          lda trymp
          sta midpos
          lda tryrp
          sta rightpos
          ldx #0
scloop   lda cipher,x
          stx savex
          jsr encrypt
          clc
          adc #65
          jsr chrout
          ldx savex
          inx
          cpx #40
          bne scloop
          rts

; === encrypt ===
; a = letter (0-25) in/out
; no plugboard (identity)
encrypt   pha
          jsr step
          pla
          ; right fwd
          ldx rightsel
          jsr setfwd
          ldx rightpos
          jsr rotorpass
          ; middle fwd
          ldx midsel
          jsr setfwd
          ldx midpos
          jsr rotorpass
          ; left fwd
          ldx leftsel
          jsr setfwd
          ldx leftpos
          jsr rotorpass
          ; reflector
          tax
          lda reflector,x
          ; left inv
          ldx leftsel
          jsr setinv
          ldx leftpos
          jsr rotorpass
          ; middle inv
          ldx midsel
          jsr setinv
          ldx midpos
          jsr rotorpass
          ; right inv
          ldx rightsel
          jsr setinv
          ldx rightpos
          jsr rotorpass
          rts

; === step rotors ===
; dual notch for vi-viii
step
          ldx midsel
          lda midpos
          cmp notch1,x
          beq dodouble
          cmp notch2,x
          bne nodouble
dodouble
          ; double step
          lda leftpos
          clc
          adc #1
          jsr mod26
          sta leftpos
          lda midpos
          clc
          adc #1
          jsr mod26
          sta midpos
          jmp stepright
nodouble
          ldx rightsel
          lda rightpos
          cmp notch1,x
          beq domid
          cmp notch2,x
          bne stepright
domid    lda midpos
          clc
          adc #1
          jsr mod26
          sta midpos
stepright
          lda rightpos
          clc
          adc #1
          jsr mod26
          sta rightpos
          rts

; === mod26 ===
mod26     cmp #26
          bcc m26done
          sbc #26
m26done   rts

; === rotor pass ===
; mod26 inlined to save 24 cycles per call
rotorpass
          stx temp
          clc
          adc temp
          cmp #26
          bcc rp1
          sbc #26
rp1       tay
          lda (ptr),y
          sec
          sbc temp
          clc
          adc #26
          cmp #26
          bcc rp2
          sbc #26
rp2       rts

; === set table pointer ===
setfwd   ldy fwdlo,x
          sty ptr
          ldy fwdhi,x
          sty ptr+1
          rts

setinv   ldy invlo,x
          sty ptr
          ldy invhi,x
          sty ptr+1
          rts

; === print string ===
; x=lo, y=hi, null-terminated
print     stx ptr
          sty ptr+1
          ldy #0
ploop     lda (ptr),y
          beq pdone
          jsr chrout
          iny
          bne ploop
pdone     rts

; === print rotor name ===
; x = rotor index (0-7)
printrn
          lda rnlo,x
          sta ptr
          lda rnhi,x
          sta ptr+1
          ldy #0
rnloop    lda (ptr),y
          beq rndone
          jsr chrout
          iny
          bne rnloop
rndone    rts

; === jiffy clock to seconds ===
; divide 24-bit jiffy by 60
; print result as decimal
jiffysec
          ; add remaining jiffies to accumulator
          sei
          clc
          lda jtotal
          adc $a2
          sta dividend+3
          lda jtotal+1
          adc $a1
          sta dividend+2
          lda jtotal+2
          adc $a0
          sta dividend+1
          lda jtotal+3
          adc #0
          sta dividend
          cli
          ; 32-bit divide by 60
          lda #0
          sta remainder
          ldx #32
jsloop    asl dividend+3
          rol dividend+2
          rol dividend+1
          rol dividend
          rol remainder
          lda remainder
          cmp #60
          bcc jsskip
          sbc #60
          sta remainder
          inc dividend+3
jsskip    dex
          bne jsloop
          ; result is in dividend (32-bit seconds)
          ; divide again by 3600 to get hours
          ; store seconds for later
          lda dividend
          sta jsecs
          lda dividend+1
          sta jsecs+1
          lda dividend+2
          sta jsecs+2
          lda dividend+3
          sta jsecs+3
          ; divide 32-bit seconds by 3600
          ; first by 60 to get minutes
          lda #0
          sta remainder
          ldx #32
jsloop2   asl jsecs+3
          rol jsecs+2
          rol jsecs+1
          rol jsecs
          rol remainder
          lda remainder
          cmp #60
          bcc jsskp2
          sbc #60
          sta remainder
          inc jsecs+3
jsskp2    dex
          bne jsloop2
          ; remainder = leftover minutes
          ; jsecs = total minutes
          ; save leftover minutes * 60 = leftover secs
          ; (we'll skip sub-minute precision)
          ; divide minutes by 60 to get hours
          lda #0
          sta remainder
          ldx #32
jsloop3   asl jsecs+3
          rol jsecs+2
          rol jsecs+1
          rol jsecs
          rol remainder
          lda remainder
          cmp #60
          bcc jsskp3
          sbc #60
          sta remainder
          inc jsecs+3
jsskp3    dex
          bne jsloop3
          ; jsecs = hours, remainder = leftover mins
          ; print hours
          lda jsecs+2
          ldx jsecs+3
          jsr $bdcd
          lda #72  ; 'h'
          jsr chrout
          lda #32
          jsr chrout
          ; print remaining minutes
          lda #0
          ldx remainder
          jsr $bdcd
          lda #77  ; 'm'
          jsr chrout
          rts

dividend  .byte 0,0,0,0
jsecs     .byte 0,0,0,0
remainder .byte 0

; === data ===

; search state
savex     .byte 0
jtotal    .byte 0,0,0,0
tryl     .byte 0
trym     .byte 0
tryr     .byte 0
trylp    .byte 0
trymp    .byte 0
tryrp    .byte 0

; rotor config
rightsel .byte 0
midsel   .byte 0
leftsel  .byte 0

; ic state
iclo     .byte 0
ichi     .byte 0
candlo   .byte 0
candhi   .byte 0

; frequency table (26 bytes)
freq      .repeat 26,0

; ciphertext (60 chars, 0-25)
cipher    .byte 24,3,12,0,14,8
          .byte 6,12,15,16,25,15
          .byte 5,21,17,2,8,6
          .byte 8,8,10,9,21,4
          .byte 2,1,3,13,15,3
          .byte 8,19,1,24,17,24
          .byte 13,10,14,2,13,9
          .byte 7,8,8,21,22,23
          .byte 24,20,9,1,2,3
          .byte 24,6,10,21,7,22

; notch positions (i-viii)
notch1    .byte 16,4,21,9,25
          .byte 25,25,25
; second notch ($ff = none)
notch2    .byte $ff,$ff,$ff,$ff,$ff
          .byte 12,12,12

; address tables (rotors i-viii)
fwdlo    .byte <rot1f,<rot2f
          .byte <rot3f,<rot4f
          .byte <rot5f,<rot6f
          .byte <rot7f,<rot8f
fwdhi    .byte >rot1f,>rot2f
          .byte >rot3f,>rot4f
          .byte >rot5f,>rot6f
          .byte >rot7f,>rot8f
invlo    .byte <rot1i,<rot2i
          .byte <rot3i,<rot4i
          .byte <rot5i,<rot6i
          .byte <rot7i,<rot8i
invhi    .byte >rot1i,>rot2i
          .byte >rot3i,>rot4i
          .byte >rot5i,>rot6i
          .byte >rot7i,>rot8i

; === rotor wiring ===

; i: ekmflgdqvzntowyhxuspaibrcj
rot1f    .byte 4,10,12,5,11,6
          .byte 3,16,21,25,13,19
          .byte 14,22,24,7,23,20
          .byte 18,15,0,8,1,17
          .byte 2,9

; ii: ajdksiruxblhwtmcqgznpyfvoe
rot2f    .byte 0,9,3,10,18,8
          .byte 17,20,23,1,11,7
          .byte 22,19,12,2,16,6
          .byte 25,13,15,24,5,21
          .byte 14,4

; iii: bdfhjlcprtxvznyeiwgakmusqo
rot3f    .byte 1,3,5,7,9,11
          .byte 2,15,17,19,23,21
          .byte 25,13,24,4,8,22
          .byte 6,0,10,12,20,18
          .byte 16,14

; iv: esovpzjayquirhxlnftgkdcmwb
rot4f    .byte 4,18,14,21,15,25
          .byte 9,0,24,16,20,8
          .byte 17,7,23,11,13,5
          .byte 19,6,10,3,2,12
          .byte 22,1

; v: vzbrgityupsdnhlxawmjqofeck
rot5f    .byte 21,25,1,17,6,8
          .byte 19,24,20,15,18,3
          .byte 13,7,11,23,0,22
          .byte 12,9,16,14,5,4
          .byte 2,10

; vi: jpgvoumfyqbenhzrdkasxlictw
rot6f    .byte 9,15,6,21,14,20
          .byte 12,5,24,16,1,4
          .byte 13,7,25,17,3,10
          .byte 0,18,23,11,8,2
          .byte 19,22

; vii: nzjhgrcxmyswboufaivlpekqdt
rot7f    .byte 13,25,9,7,6,17
          .byte 2,23,12,24,18,22
          .byte 1,14,20,5,0,8
          .byte 21,11,15,4,10,16
          .byte 3,19

; viii: fkqhtlxocbjspdzramewniuygv
rot8f    .byte 5,10,16,7,19,11
          .byte 23,14,2,1,9,18
          .byte 15,3,25,17,0,12
          .byte 4,22,13,8,20,24
          .byte 6,21

; inverse tables

rot1i    .byte 20,22,24,6,0,3
          .byte 5,15,21,25,1,4
          .byte 2,10,12,19,7,23
          .byte 18,11,17,8,13,16
          .byte 14,9

rot2i    .byte 0,9,15,2,25,22
          .byte 17,11,5,1,3,10
          .byte 14,19,24,20,16,6
          .byte 4,13,7,23,12,8
          .byte 21,18

rot3i    .byte 19,0,6,1,15,2
          .byte 18,3,16,4,20,5
          .byte 21,13,25,7,24,8
          .byte 23,9,22,11,17,10
          .byte 14,12

rot4i    .byte 7,25,22,21,0,17
          .byte 19,13,11,6,20,15
          .byte 23,16,2,4,9,12
          .byte 1,18,10,3,24,14
          .byte 8,5

rot5i    .byte 16,2,24,11,23,22
          .byte 4,13,5,19,25,14
          .byte 18,12,21,9,20,3
          .byte 10,6,8,0,17,15
          .byte 7,1

rot6i    .byte 18,10,23,16,11,7
          .byte 2,13,22,0,17,21
          .byte 6,12,4,1,9,15
          .byte 19,24,5,3,25,20
          .byte 8,14

rot7i    .byte 16,12,6,24,21,15
          .byte 4,3,17,2,22,19
          .byte 8,0,13,20,23,5
          .byte 10,25,14,18,11,7
          .byte 9,1

rot8i    .byte 16,9,8,13,18,0
          .byte 24,3,21,10,1,5
          .byte 17,20,7,12,2,15
          .byte 11,4,22,25,19,6
          .byte 23,14

; ukw-b reflector
reflector .byte 24,17,20,7,16,18
          .byte 11,3,15,23,13,6
          .byte 14,10,12,8,4,1
          .byte 5,25,2,22,21,9
          .byte 0,19

; === strings (petscii) ===

; "  enigma ic attack"
stitle   .byte 32,32,69,78,73,71
          .byte 77,65,32,73,67,32
          .byte 65,84,84,65,67,75
          .byte 0
; "  no crib needed"
ssub     .byte 32,32,78,79,32,67
          .byte 82,73,66,32,78,69
          .byte 69,68,69,68,0
; "  searching..."
ssearch  .byte 32,32,83,69,65,82
          .byte 67,72,73,78,71,46
          .byte 46,46,0
; "  total: "
stotal   .byte 32,32,84,79,84,65
          .byte 76,58,32,0
; " candidates"
scands   .byte 32,67,65,78,68,73
          .byte 68,65,84,69,83,0
; "  time: "
stime    .byte 32,32,84,73,77,69
          .byte 58,32,0
; " seconds"
ssec     .byte 32,83,69,67,79,78
          .byte 68,83,0

; rotor names (petscii)
rn1       .byte 73,0
rn2       .byte 73,73,0
rn3       .byte 73,73,73,0
rn4       .byte 73,86,0
rn5       .byte 86,0
rn6       .byte 86,73,0
rn7       .byte 86,73,73,0
rn8       .byte 86,73,73,73,0
rnlo     .byte <rn1,<rn2,<rn3
          .byte <rn4,<rn5,<rn6
          .byte <rn7,<rn8
rnhi     .byte >rn1,>rn2,>rn3
          .byte >rn4,>rn5,>rn6
          .byte >rn7,>rn8
