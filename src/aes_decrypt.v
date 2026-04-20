module INV_AES(
    input clk,
    input rst,
    input start,
    input [127:0] cipher,
    input [127:0] key,
    output reg [127:0] plaintext,
    output reg done
);

// Internal registers
reg [127:0] state_data;
reg [127:0] round_key [0:10];
reg [3:0] round;
reg [3:0] fsm_state;
reg [31:0] rcon [0:9];
reg [7:0] invs [0:255];
reg [7:0] sbox [0:255];
initial begin

// 0x00 - 0x0F
sbox[8'h00]=8'h63; sbox[8'h01]=8'h7c; sbox[8'h02]=8'h77; sbox[8'h03]=8'h7b;
sbox[8'h04]=8'hf2; sbox[8'h05]=8'h6b; sbox[8'h06]=8'h6f; sbox[8'h07]=8'hc5;
sbox[8'h08]=8'h30; sbox[8'h09]=8'h01; sbox[8'h0a]=8'h67; sbox[8'h0b]=8'h2b;
sbox[8'h0c]=8'hfe; sbox[8'h0d]=8'hd7; sbox[8'h0e]=8'hab; sbox[8'h0f]=8'h76;

// 0x10 - 0x1F
sbox[8'h10]=8'hca; sbox[8'h11]=8'h82; sbox[8'h12]=8'hc9; sbox[8'h13]=8'h7d;
sbox[8'h14]=8'hfa; sbox[8'h15]=8'h59; sbox[8'h16]=8'h47; sbox[8'h17]=8'hf0;
sbox[8'h18]=8'had; sbox[8'h19]=8'hd4; sbox[8'h1a]=8'ha2; sbox[8'h1b]=8'haf;
sbox[8'h1c]=8'h9c; sbox[8'h1d]=8'ha4; sbox[8'h1e]=8'h72; sbox[8'h1f]=8'hc0;

// 0x20 - 0x2F
sbox[8'h20]=8'hb7; sbox[8'h21]=8'hfd; sbox[8'h22]=8'h93; sbox[8'h23]=8'h26;
sbox[8'h24]=8'h36; sbox[8'h25]=8'h3f; sbox[8'h26]=8'hf7; sbox[8'h27]=8'hcc;
sbox[8'h28]=8'h34; sbox[8'h29]=8'ha5; sbox[8'h2a]=8'he5; sbox[8'h2b]=8'hf1;
sbox[8'h2c]=8'h71; sbox[8'h2d]=8'hd8; sbox[8'h2e]=8'h31; sbox[8'h2f]=8'h15;

// 0x30 - 0x3F
sbox[8'h30]=8'h04; sbox[8'h31]=8'hc7; sbox[8'h32]=8'h23; sbox[8'h33]=8'hc3;
sbox[8'h34]=8'h18; sbox[8'h35]=8'h96; sbox[8'h36]=8'h05; sbox[8'h37]=8'h9a;
sbox[8'h38]=8'h07; sbox[8'h39]=8'h12; sbox[8'h3a]=8'h80; sbox[8'h3b]=8'he2;
sbox[8'h3c]=8'heb; sbox[8'h3d]=8'h27; sbox[8'h3e]=8'hb2; sbox[8'h3f]=8'h75;

// 0x40 - 0x4F
sbox[8'h40]=8'h09; sbox[8'h41]=8'h83; sbox[8'h42]=8'h2c; sbox[8'h43]=8'h1a;
sbox[8'h44]=8'h1b; sbox[8'h45]=8'h6e; sbox[8'h46]=8'h5a; sbox[8'h47]=8'ha0;
sbox[8'h48]=8'h52; sbox[8'h49]=8'h3b; sbox[8'h4a]=8'hd6; sbox[8'h4b]=8'hb3;
sbox[8'h4c]=8'h29; sbox[8'h4d]=8'he3; sbox[8'h4e]=8'h2f; sbox[8'h4f]=8'h84;

// 0x50 - 0x5F
sbox[8'h50]=8'h53; sbox[8'h51]=8'hd1; sbox[8'h52]=8'h00; sbox[8'h53]=8'hed;
sbox[8'h54]=8'h20; sbox[8'h55]=8'hfc; sbox[8'h56]=8'hb1; sbox[8'h57]=8'h5b;
sbox[8'h58]=8'h6a; sbox[8'h59]=8'hcb; sbox[8'h5a]=8'hbe; sbox[8'h5b]=8'h39;
sbox[8'h5c]=8'h4a; sbox[8'h5d]=8'h4c; sbox[8'h5e]=8'h58; sbox[8'h5f]=8'hcf;

// 0x60 - 0x6F
sbox[8'h60]=8'hd0; sbox[8'h61]=8'hef; sbox[8'h62]=8'haa; sbox[8'h63]=8'hfb;
sbox[8'h64]=8'h43; sbox[8'h65]=8'h4d; sbox[8'h66]=8'h33; sbox[8'h67]=8'h85;
sbox[8'h68]=8'h45; sbox[8'h69]=8'hf9; sbox[8'h6a]=8'h02; sbox[8'h6b]=8'h7f;
sbox[8'h6c]=8'h50; sbox[8'h6d]=8'h3c; sbox[8'h6e]=8'h9f; sbox[8'h6f]=8'ha8;

// 0x70 - 0x7F
sbox[8'h70]=8'h51; sbox[8'h71]=8'ha3; sbox[8'h72]=8'h40; sbox[8'h73]=8'h8f;
sbox[8'h74]=8'h92; sbox[8'h75]=8'h9d; sbox[8'h76]=8'h38; sbox[8'h77]=8'hf5;
sbox[8'h78]=8'hbc; sbox[8'h79]=8'hb6; sbox[8'h7a]=8'hda; sbox[8'h7b]=8'h21;
sbox[8'h7c]=8'h10; sbox[8'h7d]=8'hff; sbox[8'h7e]=8'hf3; sbox[8'h7f]=8'hd2;

// 0x80 - 0x8F
sbox[8'h80]=8'hcd; sbox[8'h81]=8'h0c; sbox[8'h82]=8'h13; sbox[8'h83]=8'hec;
sbox[8'h84]=8'h5f; sbox[8'h85]=8'h97; sbox[8'h86]=8'h44; sbox[8'h87]=8'h17;
sbox[8'h88]=8'hc4; sbox[8'h89]=8'ha7; sbox[8'h8a]=8'h7e; sbox[8'h8b]=8'h3d;
sbox[8'h8c]=8'h64; sbox[8'h8d]=8'h5d; sbox[8'h8e]=8'h19; sbox[8'h8f]=8'h73;

// 0x90 - 0x9F
sbox[8'h90]=8'h60; sbox[8'h91]=8'h81; sbox[8'h92]=8'h4f; sbox[8'h93]=8'hdc;
sbox[8'h94]=8'h22; sbox[8'h95]=8'h2a; sbox[8'h96]=8'h90; sbox[8'h97]=8'h88;
sbox[8'h98]=8'h46; sbox[8'h99]=8'hee; sbox[8'h9a]=8'hb8; sbox[8'h9b]=8'h14;
sbox[8'h9c]=8'hde; sbox[8'h9d]=8'h5e; sbox[8'h9e]=8'h0b; sbox[8'h9f]=8'hdb;

// 0xA0 - 0xAF
sbox[8'ha0]=8'he0; sbox[8'ha1]=8'h32; sbox[8'ha2]=8'h3a; sbox[8'ha3]=8'h0a;
sbox[8'ha4]=8'h49; sbox[8'ha5]=8'h06; sbox[8'ha6]=8'h24; sbox[8'ha7]=8'h5c;
sbox[8'ha8]=8'hc2; sbox[8'ha9]=8'hd3; sbox[8'haa]=8'hac; sbox[8'hab]=8'h62;
sbox[8'hac]=8'h91; sbox[8'had]=8'h95; sbox[8'hae]=8'he4; sbox[8'haf]=8'h79;

// 0xB0 - 0xBF
sbox[8'hb0]=8'he7; sbox[8'hb1]=8'hc8; sbox[8'hb2]=8'h37; sbox[8'hb3]=8'h6d;
sbox[8'hb4]=8'h8d; sbox[8'hb5]=8'hd5; sbox[8'hb6]=8'h4e; sbox[8'hb7]=8'ha9;
sbox[8'hb8]=8'h6c; sbox[8'hb9]=8'h56; sbox[8'hba]=8'hf4; sbox[8'hbb]=8'hea;
sbox[8'hbc]=8'h65; sbox[8'hbd]=8'h7a; sbox[8'hbe]=8'hae; sbox[8'hbf]=8'h08;

// 0xC0 - 0xCF
sbox[8'hc0]=8'hba; sbox[8'hc1]=8'h78; sbox[8'hc2]=8'h25; sbox[8'hc3]=8'h2e;
sbox[8'hc4]=8'h1c; sbox[8'hc5]=8'ha6; sbox[8'hc6]=8'hb4; sbox[8'hc7]=8'hc6;
sbox[8'hc8]=8'he8; sbox[8'hc9]=8'hdd; sbox[8'hca]=8'h74; sbox[8'hcb]=8'h1f;
sbox[8'hcc]=8'h4b; sbox[8'hcd]=8'hbd; sbox[8'hce]=8'h8b; sbox[8'hcf]=8'h8a;

// 0xD0 - 0xDF
sbox[8'hd0]=8'h70; sbox[8'hd1]=8'h3e; sbox[8'hd2]=8'hb5; sbox[8'hd3]=8'h66;
sbox[8'hd4]=8'h48; sbox[8'hd5]=8'h03; sbox[8'hd6]=8'hf6; sbox[8'hd7]=8'h0e;
sbox[8'hd8]=8'h61; sbox[8'hd9]=8'h35; sbox[8'hda]=8'h57; sbox[8'hdb]=8'hb9;
sbox[8'hdc]=8'h86; sbox[8'hdd]=8'hc1; sbox[8'hde]=8'h1d; sbox[8'hdf]=8'h9e;

// 0xE0 - 0xEF
sbox[8'he0]=8'he1; sbox[8'he1]=8'hf8; sbox[8'he2]=8'h98; sbox[8'he3]=8'h11;
sbox[8'he4]=8'h69; sbox[8'he5]=8'hd9; sbox[8'he6]=8'h8e; sbox[8'he7]=8'h94;
sbox[8'he8]=8'h9b; sbox[8'he9]=8'h1e; sbox[8'hea]=8'h87; sbox[8'heb]=8'he9;
sbox[8'hec]=8'hce; sbox[8'hed]=8'h55; sbox[8'hee]=8'h28; sbox[8'hef]=8'hdf;

// 0xF0 - 0xFF
sbox[8'hf0]=8'h8c; sbox[8'hf1]=8'ha1; sbox[8'hf2]=8'h89; sbox[8'hf3]=8'h0d;
sbox[8'hf4]=8'hbf; sbox[8'hf5]=8'he6; sbox[8'hf6]=8'h42; sbox[8'hf7]=8'h68;
sbox[8'hf8]=8'h41; sbox[8'hf9]=8'h99; sbox[8'hfa]=8'h2d; sbox[8'hfb]=8'h0f;
sbox[8'hfc]=8'hb0; sbox[8'hfd]=8'h54; sbox[8'hfe]=8'hbb; sbox[8'hff]=8'h16;

end
initial begin
    invs[8'h00]=8'h52; invs[8'h01]=8'h09; invs[8'h02]=8'h6A; invs[8'h03]=8'hD5;
    invs[8'h04]=8'h30; invs[8'h05]=8'h36; invs[8'h06]=8'hA5; invs[8'h07]=8'h38;
    invs[8'h08]=8'hBF; invs[8'h09]=8'h40; invs[8'h0A]=8'hA3; invs[8'h0B]=8'h9E;
    invs[8'h0C]=8'h81; invs[8'h0D]=8'hF3; invs[8'h0E]=8'hD7; invs[8'h0F]=8'hFB;

    invs[8'h10]=8'h7C; invs[8'h11]=8'hE3; invs[8'h12]=8'h39; invs[8'h13]=8'h82;
    invs[8'h14]=8'h9B; invs[8'h15]=8'h2F; invs[8'h16]=8'hFF; invs[8'h17]=8'h87;
    invs[8'h18]=8'h34; invs[8'h19]=8'h8E; invs[8'h1A]=8'h43; invs[8'h1B]=8'h44;
    invs[8'h1C]=8'hC4; invs[8'h1D]=8'hDE; invs[8'h1E]=8'hE9; invs[8'h1F]=8'hCB;

    invs[8'h20]=8'h54; invs[8'h21]=8'h7B; invs[8'h22]=8'h94; invs[8'h23]=8'h32;
    invs[8'h24]=8'hA6; invs[8'h25]=8'hC2; invs[8'h26]=8'h23; invs[8'h27]=8'h3D;
    invs[8'h28]=8'hEE; invs[8'h29]=8'h4C; invs[8'h2A]=8'h95; invs[8'h2B]=8'h0B;
    invs[8'h2C]=8'h42; invs[8'h2D]=8'hFA; invs[8'h2E]=8'hC3; invs[8'h2F]=8'h4E;

    invs[8'h30]=8'h08; invs[8'h31]=8'h2E; invs[8'h32]=8'hA1; invs[8'h33]=8'h66;
    invs[8'h34]=8'h28; invs[8'h35]=8'hD9; invs[8'h36]=8'h24; invs[8'h37]=8'hB2;
    invs[8'h38]=8'h76; invs[8'h39]=8'h5B; invs[8'h3A]=8'hA2; invs[8'h3B]=8'h49;
    invs[8'h3C]=8'h6D; invs[8'h3D]=8'h8B; invs[8'h3E]=8'hD1; invs[8'h3F]=8'h25;

    invs[8'h40]=8'h72; invs[8'h41]=8'hF8; invs[8'h42]=8'hF6; invs[8'h43]=8'h64;
    invs[8'h44]=8'h86; invs[8'h45]=8'h68; invs[8'h46]=8'h98; invs[8'h47]=8'h16;
    invs[8'h48]=8'hD4; invs[8'h49]=8'hA4; invs[8'h4A]=8'h5C; invs[8'h4B]=8'hCC;
    invs[8'h4C]=8'h5D; invs[8'h4D]=8'h65; invs[8'h4E]=8'hB6; invs[8'h4F]=8'h92;

    invs[8'h50]=8'h6C; invs[8'h51]=8'h70; invs[8'h52]=8'h48; invs[8'h53]=8'h50;
    invs[8'h54]=8'hFD; invs[8'h55]=8'hED; invs[8'h56]=8'hB9; invs[8'h57]=8'hDA;
    invs[8'h58]=8'h5E; invs[8'h59]=8'h15; invs[8'h5A]=8'h46; invs[8'h5B]=8'h57;
    invs[8'h5C]=8'hA7; invs[8'h5D]=8'h8D; invs[8'h5E]=8'h9D; invs[8'h5F]=8'h84;

    invs[8'h60]=8'h90; invs[8'h61]=8'hD8; invs[8'h62]=8'hAB; invs[8'h63]=8'h00;
    invs[8'h64]=8'h8C; invs[8'h65]=8'hBC; invs[8'h66]=8'hD3; invs[8'h67]=8'h0A;
    invs[8'h68]=8'hF7; invs[8'h69]=8'hE4; invs[8'h6A]=8'h58; invs[8'h6B]=8'h05;
    invs[8'h6C]=8'hB8; invs[8'h6D]=8'hB3; invs[8'h6E]=8'h45; invs[8'h6F]=8'h06;

    invs[8'h70]=8'hD0; invs[8'h71]=8'h2C; invs[8'h72]=8'h1E; invs[8'h73]=8'h8F;
    invs[8'h74]=8'hCA; invs[8'h75]=8'h3F; invs[8'h76]=8'h0F; invs[8'h77]=8'h02;
    invs[8'h78]=8'hC1; invs[8'h79]=8'hAF; invs[8'h7A]=8'hBD; invs[8'h7B]=8'h03;
    invs[8'h7C]=8'h01; invs[8'h7D]=8'h13; invs[8'h7E]=8'h8A; invs[8'h7F]=8'h6B;

    invs[8'h80]=8'h3A; invs[8'h81]=8'h91; invs[8'h82]=8'h11; invs[8'h83]=8'h41;
    invs[8'h84]=8'h4F; invs[8'h85]=8'h67; invs[8'h86]=8'hDC; invs[8'h87]=8'hEA;
    invs[8'h88]=8'h97; invs[8'h89]=8'hF2; invs[8'h8A]=8'hCF; invs[8'h8B]=8'hCE;
    invs[8'h8C]=8'hF0; invs[8'h8D]=8'hB4; invs[8'h8E]=8'hE6; invs[8'h8F]=8'h73;

    invs[8'h90]=8'h96; invs[8'h91]=8'hAC; invs[8'h92]=8'h74; invs[8'h93]=8'h22;
    invs[8'h94]=8'hE7; invs[8'h95]=8'hAD; invs[8'h96]=8'h35; invs[8'h97]=8'h85;
    invs[8'h98]=8'hE2; invs[8'h99]=8'hF9; invs[8'h9A]=8'h37; invs[8'h9B]=8'hE8;
    invs[8'h9C]=8'h1C; invs[8'h9D]=8'h75; invs[8'h9E]=8'hDF; invs[8'h9F]=8'h6E;

    invs[8'hA0]=8'h47; invs[8'hA1]=8'hF1; invs[8'hA2]=8'h1A; invs[8'hA3]=8'h71;
    invs[8'hA4]=8'h1D; invs[8'hA5]=8'h29; invs[8'hA6]=8'hC5; invs[8'hA7]=8'h89;
    invs[8'hA8]=8'h6F; invs[8'hA9]=8'hB7; invs[8'hAA]=8'h62; invs[8'hAB]=8'h0E;
    invs[8'hAC]=8'hAA; invs[8'hAD]=8'h18; invs[8'hAE]=8'hBE; invs[8'hAF]=8'h1B;

    invs[8'hB0]=8'hFC; invs[8'hB1]=8'h56; invs[8'hB2]=8'h3E; invs[8'hB3]=8'h4B;
    invs[8'hB4]=8'hC6; invs[8'hB5]=8'hD2; invs[8'hB6]=8'h79; invs[8'hB7]=8'h20;
    invs[8'hB8]=8'h9A; invs[8'hB9]=8'hDB; invs[8'hBA]=8'hC0; invs[8'hBB]=8'hFE;
    invs[8'hBC]=8'h78; invs[8'hBD]=8'hCD; invs[8'hBE]=8'h5A; invs[8'hBF]=8'hF4;

    invs[8'hC0]=8'h1F; invs[8'hC1]=8'hDD; invs[8'hC2]=8'hA8; invs[8'hC3]=8'h33;
    invs[8'hC4]=8'h88; invs[8'hC5]=8'h07; invs[8'hC6]=8'hC7; invs[8'hC7]=8'h31;
    invs[8'hC8]=8'hB1; invs[8'hC9]=8'h12; invs[8'hCA]=8'h10; invs[8'hCB]=8'h59;
    invs[8'hCC]=8'h27; invs[8'hCD]=8'h80; invs[8'hCE]=8'hEC; invs[8'hCF]=8'h5F;

    invs[8'hD0]=8'h60; invs[8'hD1]=8'h51; invs[8'hD2]=8'h7F; invs[8'hD3]=8'hA9;
    invs[8'hD4]=8'h19; invs[8'hD5]=8'hB5; invs[8'hD6]=8'h4A; invs[8'hD7]=8'h0D;
    invs[8'hD8]=8'h2D; invs[8'hD9]=8'hE5; invs[8'hDA]=8'h7A; invs[8'hDB]=8'h9F;
    invs[8'hDC]=8'h93; invs[8'hDD]=8'hC9; invs[8'hDE]=8'h9C; invs[8'hDF]=8'hEF;

    invs[8'hE0]=8'hA0; invs[8'hE1]=8'hE0; invs[8'hE2]=8'h3B; invs[8'hE3]=8'h4D;
    invs[8'hE4]=8'hAE; invs[8'hE5]=8'h2A; invs[8'hE6]=8'hF5; invs[8'hE7]=8'hB0;
    invs[8'hE8]=8'hC8; invs[8'hE9]=8'hEB; invs[8'hEA]=8'hBB; invs[8'hEB]=8'h3C;
    invs[8'hEC]=8'h83; invs[8'hED]=8'h53; invs[8'hEE]=8'h99; invs[8'hEF]=8'h61;

    invs[8'hF0]=8'h17; invs[8'hF1]=8'h2B; invs[8'hF2]=8'h04; invs[8'hF3]=8'h7E;
    invs[8'hF4]=8'hBA; invs[8'hF5]=8'h77; invs[8'hF6]=8'hD6; invs[8'hF7]=8'h26;
    invs[8'hF8]=8'hE1; invs[8'hF9]=8'h69; invs[8'hFA]=8'h14; invs[8'hFB]=8'h63;
    invs[8'hFC]=8'h55; invs[8'hFD]=8'h21; invs[8'hFE]=8'h0C; invs[8'hFF]=8'h7D;
end
initial begin
    rcon[0] = 32'h01000000;
    rcon[1] = 32'h02000000;
    rcon[2] = 32'h04000000;
    rcon[3] = 32'h08000000;
    rcon[4] = 32'h10000000;
    rcon[5] = 32'h20000000;
    rcon[6] = 32'h40000000;
    rcon[7] = 32'h80000000;
    rcon[8] = 32'h1B000000;
    rcon[9] = 32'h36000000;
end
function [127:0] inv_sub_bytes;
input [127:0] data;
integer i;
begin
    for(i = 0; i < 16; i = i + 1)
    begin
        inv_sub_bytes[i*8 +: 8] = invs[data[i*8 +: 8]];
    end
end
endfunction
function [7:0] xtime;
    input [7:0] x;
    begin
        xtime = (x[7]) ? ((x << 1) ^ 8'h1B) : (x << 1);
    end
endfunction
function [7:0] mul02;
    input [7:0] x;
    begin
        mul02 = xtime(x);
    end
endfunction
function [7:0] mul03;
    input [7:0] x;
    begin
        mul03 = xtime(x) ^ x;
    end
endfunction

function [7:0] mul04;
input [7:0] x;
begin
    mul04 = xtime(xtime(x));
end
endfunction

function [7:0] mul08;
input [7:0] x;
begin
    mul08 = xtime(xtime(xtime(x)));
end
endfunction

function [7:0] mul09;
input [7:0] x;
begin
    mul09 = mul08(x) ^ x;
end
endfunction

function [7:0] mul0B;
input [7:0] x;
begin
    mul0B = mul08(x) ^ mul02(x) ^ x;
end
endfunction

function [7:0] mul0D;
input [7:0] x;
begin
    mul0D = mul08(x) ^ mul04(x) ^ x;
end
endfunction

function [7:0] mul0E;
input [7:0] x;
begin
    mul0E = mul08(x) ^ mul04(x) ^ mul02(x);
end
endfunction

function [127:0] invmixcolumns;
input [127:0] data;
begin
    // Column 1
    invmixcolumns[127:120] = mul0E(data[127:120]) ^ mul0B(data[119:112]) ^ mul0D(data[111:104]) ^ mul09(data[103:96]);
    invmixcolumns[119:112] = mul09(data[127:120]) ^ mul0E(data[119:112]) ^ mul0B(data[111:104]) ^ mul0D(data[103:96]);
    invmixcolumns[111:104] = mul0D(data[127:120]) ^ mul09(data[119:112]) ^ mul0E(data[111:104]) ^ mul0B(data[103:96]);
    invmixcolumns[103:96]  = mul0B(data[127:120]) ^ mul0D(data[119:112]) ^ mul09(data[111:104]) ^ mul0E(data[103:96]);

    // Column 2
    invmixcolumns[95:88] = mul0E(data[95:88]) ^ mul0B(data[87:80]) ^ mul0D(data[79:72]) ^ mul09(data[71:64]);
    invmixcolumns[87:80] = mul09(data[95:88]) ^ mul0E(data[87:80]) ^ mul0B(data[79:72]) ^ mul0D(data[71:64]);
    invmixcolumns[79:72] = mul0D(data[95:88]) ^ mul09(data[87:80]) ^ mul0E(data[79:72]) ^ mul0B(data[71:64]);
    invmixcolumns[71:64] = mul0B(data[95:88]) ^ mul0D(data[87:80]) ^ mul09(data[79:72]) ^ mul0E(data[71:64]);

    // Column 3
    invmixcolumns[63:56] = mul0E(data[63:56]) ^ mul0B(data[55:48]) ^ mul0D(data[47:40]) ^ mul09(data[39:32]);
    invmixcolumns[55:48] = mul09(data[63:56]) ^ mul0E(data[55:48]) ^ mul0B(data[47:40]) ^ mul0D(data[39:32]);
    invmixcolumns[47:40] = mul0D(data[63:56]) ^ mul09(data[55:48]) ^ mul0E(data[47:40]) ^ mul0B(data[39:32]);
    invmixcolumns[39:32] = mul0B(data[63:56]) ^ mul0D(data[55:48]) ^ mul09(data[47:40]) ^ mul0E(data[39:32]);

    // Column 4
    invmixcolumns[31:24] = mul0E(data[31:24]) ^ mul0B(data[23:16]) ^ mul0D(data[15:8]) ^ mul09(data[7:0]);
    invmixcolumns[23:16] = mul09(data[31:24]) ^ mul0E(data[23:16]) ^ mul0B(data[15:8]) ^ mul0D(data[7:0]);
    invmixcolumns[15:8]  = mul0D(data[31:24]) ^ mul09(data[23:16]) ^ mul0E(data[15:8]) ^ mul0B(data[7:0]);
    invmixcolumns[7:0]   = mul0B(data[31:24]) ^ mul0D(data[23:16]) ^ mul09(data[15:8]) ^ mul0E(data[7:0]);
end
endfunction

function [127:0] subkey;
    input [127:0] key_in;
    input [31:0] rcon_val;

    reg [31:0] temp;
    reg [127:0] new_key;

    begin
        // Step 1: Take last 32 bits
        temp = key_in[31:0];

        // Step 2: Rotate left by 8 bits
        temp = {temp[23:0], temp[31:24]};

        // Step 3: Apply S-box to each byte
        temp[31:24] = sbox[temp[31:24]];
        temp[23:16] = sbox[temp[23:16]];
        temp[15:8]  = sbox[temp[15:8]];
        temp[7:0]   = sbox[temp[7:0]];

        // Step 4: XOR with RCON
        temp = temp^rcon_val;

        // Step 5: Generate new key words
        new_key[127:96] = key_in[127:96] ^ temp;
        new_key[95:64]  = key_in[95:64]  ^ new_key[127:96];
        new_key[63:32]  = key_in[63:32]  ^ new_key[95:64];
        new_key[31:0]   = key_in[31:0]   ^ new_key[63:32];

        subkey = new_key;
    end
endfunction
function [127:0] inv_shift_rows;
input [127:0] s;

reg [7:0] b[0:15];

begin
    b[0]  = s[127:120];
    b[1]  = s[119:112];
    b[2]  = s[111:104];
    b[3]  = s[103:96];
    b[4]  = s[95:88];
    b[5]  = s[87:80];
    b[6]  = s[79:72];
    b[7]  = s[71:64];
    b[8]  = s[63:56];
    b[9]  = s[55:48];
    b[10] = s[47:40];
    b[11] = s[39:32];
    b[12] = s[31:24];
    b[13] = s[23:16];
    b[14] = s[15:8];
    b[15] = s[7:0];

    inv_shift_rows = {
        b[0],  b[13], b[10], b[7],
        b[4],  b[1],  b[14], b[11],
        b[8],  b[5],  b[2],  b[15],
        b[12], b[9],  b[6],  b[3]
    };
end
endfunction

always @(posedge clk or posedge rst)
begin
    if(rst)
    begin
        fsm_state <= 0;
        round <= 0;
        done <= 0;
        plaintext <= 0;
        state_data <= 0;
    end
    else
    begin
        case(fsm_state)

        // ---------------- INIT ----------------
        0: begin
            done <= 0;
            if(start) begin
                state_data <= cipher;
                round_key[0] <= key;
                round <= 1;
                fsm_state <= 1;
            end
        end

        // ---------------- KEY EXPANSION ----------------
        1: begin
            if(round <= 10) begin
                round_key[round] <= subkey(round_key[round-1], rcon[round-1]);
                round <= round + 1;
            end
            else begin
                round <= 9;
                fsm_state <= 2;
            end
        end

        // ---------------- INITIAL ADD ROUND KEY ----------------
        2: begin
            state_data <= state_data ^ round_key[10];
            fsm_state <= 3;
        end

        // ---------------- MAIN LOOP ----------------
        // ? FIXED ORDER STARTS HERE

                // ---------------- MAIN DECRYPTION ROUNDS ----------------

        3: begin
            // InvShiftRows
            state_data <= inv_shift_rows(state_data);
            fsm_state <= 4;
        end

        4: begin
            // InvSubBytes
            state_data <= inv_sub_bytes(state_data);
            fsm_state <= 5;
        end

        5: begin
            // AddRoundKey
            state_data <= state_data ^ round_key[round];

            if(round > 0)
                fsm_state <= 6;
            else
                fsm_state <= 7;
        end

        6: begin
            // InvMixColumns
            state_data <= invmixcolumns(state_data);

            round <= round - 1;
            fsm_state <= 3;
        end

        // Final round complete
        7: begin
            plaintext <= state_data;
            done <= 1;
        end
        endcase
    end
end



endmodule












`timescale 1ns/1ps

module INV_AES_tb;

reg clk;
reg rst;
reg start;
reg [127:0] cipher;
reg [127:0] key;
wire [127:0] plaintext;
wire done;

// Instantiate your decryption module
INV_AES uut (
    .clk(clk),
    .rst(rst),
    .start(start),
    .cipher(cipher),
    .key(key),
    .plaintext(plaintext),
    .done(done)
);

// Clock generation
always #5 clk = ~clk;

initial begin
    clk = 0;
    rst = 1;
    start = 0;

    // ?? STANDARD AES TEST VECTOR
  key    = 128'h2b7e151628aed2a6abf7158809cf4f3c;
cipher = 128'h3925841d02dc09fbdc118597196a0b32;
    #20;
    rst = 0;

    #10;
    start = 1;

    #10;
    start = 0;

    // Wait until done
    wait(done);

    #10;

    $display("Plaintext = %h", plaintext);

    if(plaintext==128'h3243f6a8885a308d313198a2e0370734)
        $display("AES DECRYPTION CORRECT ?");
    else
        $display("AES DECRYPTION WRONG ?");

    $stop;
end

endmodule