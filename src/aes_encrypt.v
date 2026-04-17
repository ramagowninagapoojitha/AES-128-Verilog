module AES(
input clk,
input rst,
input [127:0]plaintext,
input [127:0]key,
input start,
output reg [127:0]chiphertext,
output reg done);
reg [127:0]state_data;
reg [3:0]round;
reg [127:0]round_key[0:10];
reg [3:0]fsm_state;
reg [31:0] rcon [0:9];
reg [7:0]sbox[0:255];//because we want 256 elements with each of 8 bits
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
    // RCON values for AES-128
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
function [127:0] sub_bytes;
    input [127:0] data;
    begin
        sub_bytes[127:120] = sbox[data[127:120]];
        sub_bytes[119:112] = sbox[data[119:112]];
        sub_bytes[111:104] = sbox[data[111:104]];
        sub_bytes[103:96]  = sbox[data[103:96]];
        sub_bytes[95:88]   = sbox[data[95:88]];
        sub_bytes[87:80]   = sbox[data[87:80]];
        sub_bytes[79:72]   = sbox[data[79:72]];
        sub_bytes[71:64]   = sbox[data[71:64]];
        sub_bytes[63:56]   = sbox[data[63:56]];
        sub_bytes[55:48]   = sbox[data[55:48]];
        sub_bytes[47:40]   = sbox[data[47:40]];
        sub_bytes[39:32]   = sbox[data[39:32]];
        sub_bytes[31:24]   = sbox[data[31:24]];
        sub_bytes[23:16]   = sbox[data[23:16]];
        sub_bytes[15:8]    = sbox[data[15:8]];
        sub_bytes[7:0]     = sbox[data[7:0]];
    end
endfunction
function [127:0] shift_rows;
    //first row no shift secong row left shift by1 and second row left shift by 2 AND LAST BY 3 LAFT SHIFTS
    input [127:0] s;
    begin
        shift_rows = {
            s[127:120], s[87:80],  s[47:40],  s[7:0],
            s[95:88],   s[55:48],  s[15:8],   s[103:96],
            s[63:56],   s[23:16],  s[111:104], s[71:64],
            s[31:24],   s[119:112], s[79:72],  s[39:32]
        };
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
function [127:0] mixcolumns;
    input [127:0] data;
    begin
        // Column 1
        mixcolumns[127:120] = mul02(data[127:120]) ^ mul03(data[119:112]) ^ data[111:104] ^ data[103:96];
        mixcolumns[119:112] = data[127:120] ^ mul02(data[119:112]) ^ mul03(data[111:104]) ^ data[103:96];
        mixcolumns[111:104] = data[127:120] ^ data[119:112] ^ mul02(data[111:104]) ^ mul03(data[103:96]);
        mixcolumns[103:96]  = mul03(data[127:120]) ^ data[119:112] ^ data[111:104] ^ mul02(data[103:96]);
        // Column 2
        mixcolumns[95:88] = mul02(data[95:88]) ^ mul03(data[87:80]) ^ data[79:72] ^ data[71:64];
        mixcolumns[87:80] = data[95:88] ^ mul02(data[87:80]) ^ mul03(data[79:72]) ^ data[71:64];
        mixcolumns[79:72] = data[95:88] ^ data[87:80] ^ mul02(data[79:72]) ^ mul03(data[71:64]);
        mixcolumns[71:64] = mul03(data[95:88]) ^ data[87:80] ^ data[79:72] ^ mul02(data[71:64]);

        // Column 3
        mixcolumns[63:56] = mul02(data[63:56]) ^ mul03(data[55:48]) ^ data[47:40] ^ data[39:32];
        mixcolumns[55:48] = data[63:56] ^ mul02(data[55:48]) ^ mul03(data[47:40]) ^ data[39:32];
        mixcolumns[47:40] = data[63:56] ^ data[55:48] ^ mul02(data[47:40]) ^ mul03(data[39:32]);
        mixcolumns[39:32] = mul03(data[63:56]) ^ data[55:48] ^ data[47:40] ^ mul02(data[39:32]);

        // Column 4
        mixcolumns[31:24] = mul02(data[31:24]) ^ mul03(data[23:16]) ^ data[15:8] ^ data[7:0];
        mixcolumns[23:16] = data[31:24] ^ mul02(data[23:16]) ^ mul03(data[15:8]) ^ data[7:0];
        mixcolumns[15:8]  = data[31:24] ^ data[23:16] ^ mul02(data[15:8]) ^ mul03(data[7:0]);
        mixcolumns[7:0]   = mul03(data[31:24]) ^ data[23:16] ^ data[15:8] ^ mul02(data[7:0]);
    end
endfunction

always @(posedge clk or posedge rst)
begin
if(rst)
begin
fsm_state<=0;
 round<=0;
 done<=0;
 chiphertext<=0;
 state_data<=0;
 
 end
 else
 begin
     case(fsm_state)
         0:begin
             if(start) begin
         state_data<=plaintext;
         round_key[0]<=key;
         round<=1;
           fsm_state<=1;
           end
           end
          1:
              begin
             if(round <= 10) begin
               round_key[round] <= subkey(round_key[round-1], rcon[round-1]);
                  round <= round + 1;
              end
           else begin
            round <= 1;
           fsm_state <= 2;
            end
          end             
        2: begin
            //initial addroundkey
          state_data <= state_data ^ round_key[0];
          fsm_state <= 3;
            end

         3: begin
    // SubBytes
    state_data <= sub_bytes(state_data);
    fsm_state <= 4;
            end
         4: begin
             //shift rows
    state_data <= shift_rows(state_data);
    fsm_state <= 5;
end

          5: begin
    if(round < 10)
        state_data <= mixcolumns(state_data);
    fsm_state <= 6;
end
6: begin
    state_data <= state_data ^ round_key[round];

    if(round == 10)
        fsm_state <= 7;
    else begin
        round <= round + 1;
        fsm_state <= 3;  // loop back
    end
end


          7://done signal
         begin
             done<=1;
             chiphertext<=state_data;
         end
   endcase
   end
end


endmodule



















