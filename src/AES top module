module AES_TOP(
    input clk,
    input rst,
    input start,
    input mode,                 // 0 = Encrypt, 1 = Decrypt

    input [127:0] data_in,
    input [127:0] key,

    output [127:0] data_out,
    output done
);


wire [127:0] enc_out;
wire [127:0] dec_out;

wire enc_done;
wire dec_done;



AES ENC (
    .clk(clk),
    .rst(rst),

    .plaintext(data_in),
    .key(key),

    .start(start & ~mode),

    .chiphertext(enc_out),
    .done(enc_done)
);



INV_AES DEC (
    .clk(clk),
    .rst(rst),

    .cipher(data_in),
    .key(key),

    .start(start & mode),

    .plaintext(dec_out),
    .done(dec_done)
);



assign data_out = (mode == 0) ? enc_out : dec_out;

assign done = (mode == 0) ? enc_done : dec_done;

endmodule



