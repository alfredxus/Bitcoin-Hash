module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);
							
parameter num_nonces = 16;
parameter NUM_OF_WORDS = 21;

//logic [ 4:0] state;
//logic [31:0] hout[num_nonces];

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here
enum logic [3:0] {IDLE, LOAD, READ_P1, PHASE_2, PHASE_3, WAIT, PRE_WRITE, WRITE} state;
logic [31:0] w[16][16];
logic [31:0] message[32];
logic [31:0] h_a[8];
logic [31:0] h_b[16][8];
logic [ 7:0] offset; 
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [31:0] read_buffer[20];
logic start_a, start_b, init_hash;
logic sha256_done_a;
logic sha256_done_b[16];

assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

always_ff @(posedge clk, negedge reset_n) begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    IDLE: begin 
	   if(start) begin
		  offset <= 8'b0;
		  cur_we <= 1'b0;
		  cur_addr <= message_addr;
		  start_a <= 0;	
		  start_b <= 0;	
		  state <= LOAD;
		end
    end

	 LOAD: begin 
	   state <= READ_P1;
	 end
	 
	 // Read in data and executes phase 1 
    READ_P1: begin
	   if(offset < NUM_OF_WORDS) begin
		  if(offset == 0)
		    message[offset]<= mem_read_data;
		  else
		    read_buffer[offset] <= mem_read_data;
		  if (offset > 1)
		    message[offset-2] <= read_buffer[offset-1];
		  offset <= offset + 8'b1;
		  state <= READ_P1;
	   end
	   else begin
	     for(int n = 0; n < num_nonces; n++) w[0][n] <= message[n];
		  message[20] <= 32'h80000000;
		  for(int n = 21; n < 31; n++) message[n] <= 32'b0;
		  message[31] <= 32'd640;
		  init_hash <= 1;
		  start_a <= 1;
		  state <= PHASE_2;
		end
    end			

    // Process second message block and execute phase 2
    PHASE_2: begin
	   start_a <= 0;
		if(sha256_done_a) begin
		  for (int i = 0; i < num_nonces; i++) begin
			 for (int n = 0; n < 3; n++) w[i][n] <= message[n + 16];
			 w[i][3] <= i;
			 for (int n = 4; n < 16; n++) w[i][n] <= message[n + 16];
	     end
		  init_hash <= 0;
		  start_b <= 1;
		  state <= PHASE_3;
		end
		else state <= PHASE_2;
	 end
	
    // Pad output from phase 2 and execute phase 3
    PHASE_3: begin
	   start_b <= 0;
		if(sha256_done_b[0]) begin  
		  for (int i = 0; i < num_nonces; i++) begin   
			 for (int n = 0; n < 8; n++) w[i][n] <= h_b[i][n];;
			 w[i][8] <= 32'h80000000;
			 for (int n = 9; n < 15; n++) w[i][n] <= 32'b0; 
			 w[i][15] <= 32'd256;
		  end
		  state <= WAIT;
		  init_hash <= 1;
		  start_b <= 1;
		end
		else state <= PHASE_3;
    end
	
    WAIT: begin
		state <= PRE_WRITE;
    end
	 
	 PRE_WRITE: begin
	   start_b <= 0;
		if(sha256_done_b[0]) begin
		  offset <= 8'b0;
		  cur_we <= 1'b1;
		  cur_addr <= output_addr;
		  cur_write_data <= h_b[0][0];
		  state <= WRITE;
		  end
		  else state <= PRE_WRITE;
    end
		
    WRITE: begin
	   if(offset < 15) begin
		  case(offset)
		     0: cur_write_data <= h_b[ 1][0];
			  1: cur_write_data <= h_b[ 2][0];
			  2: cur_write_data <= h_b[ 3][0];
			  3: cur_write_data <= h_b[ 4][0];
			  4: cur_write_data <= h_b[ 5][0];
			  5: cur_write_data <= h_b[ 6][0];
			  6: cur_write_data <= h_b[ 7][0];
			  7: cur_write_data <= h_b[ 8][0];
			  8: cur_write_data <= h_b[ 9][0];
			  9: cur_write_data <= h_b[10][0];
			 10: cur_write_data <= h_b[11][0];
			 11: cur_write_data <= h_b[12][0];
			 12: cur_write_data <= h_b[13][0];
			 13: cur_write_data <= h_b[14][0];
			 14: cur_write_data <= h_b[15][0];
			 default: cur_write_data <= h_b[1][0];
		  endcase
		  offset <= offset + 8'b1;
		  state <= WRITE;
		end
		else state <= IDLE;
    end
    endcase
  end

simplified_sha256 sha0 (
  .clk(clk),
  .reset_n(reset_n),
  .start(start_a),
  .message(w[0]),
  .hash(h_a),
  .k(k),
  .original_hash(init_hash),
  .done(sha256_done_a),
  .result(h_a)
);

genvar i;
generate
  for (i = 0; i < 16; i = i + 1) begin : gen_block
    simplified_sha256 sha (
	   .clk(clk),
      .reset_n(reset_n),
      .start(start_b),
      .message(w[i]),
      .hash(h_a),
      .k(k),
      .original_hash(init_hash),
      .done(sha256_done_b[i]),
      .result(h_b[i])
    );
  end
endgenerate

assign done = (state == IDLE);
	
endmodule
