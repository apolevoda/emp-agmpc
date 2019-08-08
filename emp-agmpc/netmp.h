#ifndef NETIOMP_H__
#define NETIOMP_H__
#include <emp-tool/emp-tool.h>
#include "cmpc_config.h"
#include <unordered_map>
#include <unordered_set>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
using namespace emp;

template<int nP>
class NetIOMP { public:
	NetIO*ios[nP+1];
	NetIO*ios2[nP+1];
	int party;
	bool sent[nP+1];
        const static int num_faults = nP % 3 == 0 ? nP / 3 - 1 : nP / 3;
	NetIOMP(int party, int port) {
		this->party = party;
		memset(sent, false, nP+1);
		for(int i = 1; i <= nP; ++i)for(int j = 1; j <= nP; ++j)if(i < j){
			if(i == party) {
#ifdef LOCALHOST
				ios[j] = new NetIO(IP[j], port+2*(i*nP+j), true);
#else
				ios[j] = new NetIO(IP[j], port+2*(i), true);
#endif
				ios[j]->set_nodelay();	

#ifdef LOCALHOST
				ios2[j] = new NetIO(nullptr, port+2*(i*nP+j)+1, true);
#else
				ios2[j] = new NetIO(nullptr, port+2*(j)+1, true);
#endif
				ios2[j]->set_nodelay();	
			} else if(j == party) {
#ifdef LOCALHOST
				ios[i] = new NetIO(nullptr, port+2*(i*nP+j), true);
#else
				ios[i] = new NetIO(nullptr, port+2*(i), true);
#endif
				ios[i]->set_nodelay();	

#ifdef LOCALHOST
				ios2[i] = new NetIO(IP[i], port+2*(i*nP+j)+1, true);
#else
				ios2[i] = new NetIO(IP[i], port+2*(j)+1, true);
#endif
				ios2[i]->set_nodelay();	
			}
		}
	}
	int64_t count() {
		int64_t res = 0;
#ifdef COUNT_IO
		for(int i = 1; i <= nP; ++i) if(i != party){
			res += ios[i]->counter;
			res += ios2[i]->counter;
		}
#endif
		return res;
	}

	~NetIOMP() {
		for(int i = 1; i <= nP; ++i)
			if(i != party) {
				delete ios[i];
				delete ios2[i];
			}
	}
	void send_data(int dst, const void * data, size_t len) {
		if(dst != 0 and dst!= party) {
			if(party < dst)
				ios[dst]->send_data(data, len);
			else
				ios2[dst]->send_data(data, len);
			sent[dst] = true;
		}
#ifdef __MORE_FLUSH
		flush(dst);
#endif
	}
        int recv_data(int src, void * data, size_t len) {
            if(src != 0 and src!= party) {
                if(sent[src])flush(src);
                if(src < party)
                    return ios[src]->recv_data(data, len);
                else
                    return ios2[src]->recv_data(data, len);
            }
        }
	NetIO*& get(size_t idx, bool b = false){
		if (b)
			return ios[idx];
		else return ios2[idx];
	}
	void flush(int idx = 0) {
		if(idx == 0) {
			for(int i = 1; i <= nP; ++i)
				if(i != party) {
					ios[i]->flush();
					ios2[i]->flush();
				}
		} else {
			if(party < idx)
				ios[idx]->flush();
			else
				ios2[idx]->flush();
		}
	}
	void sync() {
		for(int i = 1; i <= nP; ++i) for(int j = 1; j <= nP; ++j) if(i < j) {
			if(i == party) {
				ios[j]->sync();
				ios2[j]->sync();
			} else if(j == party) {
				ios[i]->sync();
				ios2[i]->sync();
			}
		}
	}

        int binary_ba(int *ptr, int nF = num_faults) {
            int rec_val, rec_c0, rec_c1;
            int c0 = 0;
            int c1;
            int ctr1 = 0, ctr2 = 0;

            for(int i = 1; i <= nP; ++i) {
                if(party != i) {
                    send_data(i, ptr, sizeof(int));
                    flush(i);
                    recv_data(i, &rec_val, sizeof(int));
                    if(rec_val==0) ++c0;
                }
            }

            c1 = nP - c0 - 1 >= nP - nF ? 1 : 0;
            c0 = c0 >= nP - nF ? 1 : 0;

            for(int i = 1; i <= nP; ++i) {
                if(party != i) {
                    send_data(i, &c0, sizeof(int));
                    send_data(i, &c1, sizeof(int));
                    flush(i);
                    recv_data(i, &rec_c0, sizeof(int));
                    recv_data(i, &rec_c1, sizeof(int));
                    if(rec_c0 == 1) ++ctr1;
                    if(rec_c1 == 1) ++ctr2;
                }
            }

            *ptr = ctr2 > nF ? 1 : 0;

            const int num_pks = nF+1;

            for(int i = 1; i <= num_pks; ++i) {
                if(party == i) {
                    for(int j = 1; j <= nP; ++j) {
                        if(party != j) {
                            send_data(j, ptr, sizeof(int));
                            flush(j);
                        }
                    }
                }
                if(party != i) {
                    recv_data(i, &rec_val, sizeof(int));
                    if(*ptr) {
                        if(ctr2 < nP - nF) *ptr = rec_val;
                    } else {
                        if(ctr1 < nP - nF) *ptr = rec_val;
                    }
                }
            }

            return *ptr;
        }

        int multival_ba(int *ptr, int nF = num_faults) {

            int *y = nullptr;
            int **y_ptr = &y;
            int z = 0;
            int z_ctr = 0;
            int vote = 0;
            int rec_val;

            std::unordered_map<int, int> xs;
            std::unordered_map<int, int> ys;

            std::unordered_map<int, int>::iterator iter;

            xs.insert(std::make_pair(*ptr, 1));

            for(int i = 1; i <= nP; ++i) {
                if(party != i) {
                    send_data(i, ptr, sizeof(int));
                    flush(i);
                    recv_data(i, &rec_val, sizeof(int));
                    iter = xs.find(rec_val);
                    if(iter == xs.end()) {
                        xs.insert(std::make_pair(rec_val, 1));
                    } else {
                        ++iter->second;
                    }
                }
            }

            for(auto& item : xs) {
                if(item.second >= nP - num_faults) {
                    y = (int*)malloc(sizeof(int));
                    *y = item.first;
                    ys.insert(std::make_pair(*y, 1));
                }
            }



            for(int i = 1; i <= nP; ++i) {
                if(party != i) {
                    send_data(i, y_ptr, sizeof(int*));
                    if(y != nullptr) {
                        send_data(i, y, sizeof(int));
                    }
                    flush(i);
                    recv_data(i, &ptr, sizeof(int*));
                    if(ptr != nullptr) {
                        recv_data(i, &rec_val, sizeof(int));
                        iter = ys.find(rec_val);
                        if(iter == ys.end()) {
                            ys.insert(std::make_pair(rec_val, 1));
                        } else {
                            ++iter->second;
                        }
                    }
                }
            }

            for(auto& item : ys) {
                if(item.second > z_ctr) {
                    z = item.first;
                    z_ctr = item.second;
                }
                if(item.second >= nP - num_faults) {
                    vote = 1;
                }
            }

            int bin_ba = binary_ba(&vote, nF);

            return (z_ctr > 0 && bin_ba) ? z : 0;


        }

        int binary_bc(int *ptr, int dealer, int nF = num_faults) {
            if(party == dealer) {
                for(int i = 1; i <= nP; ++i) {
                    if(party != i) {
                        send_data(i, ptr, sizeof(ptr));
                        flush(i);
                    }
                }
                binary_ba(ptr, nF);
                return *ptr;
            } else {
                recv_data(dealer, ptr, sizeof(int*));
                return binary_ba(ptr, nF);
            }
        }

        int multival_bc(int *ptr, int dealer, int nF = num_faults) {
            if(party == dealer) {
                for(int i = 1; i <= nP; ++i) {
                    if(party != i) {
                        send_data(i, ptr, sizeof(ptr));
                        flush(i);
                    }
                }
                multival_ba(ptr, nF);
                return *ptr;
            } else {
                recv_data(dealer, ptr, sizeof(int*));
                return multival_ba(ptr, nF);
            }
        }

        void auth_bc_send(Hash *hash, int *val, int round, int *val_indices, unsigned char **val_signatures,
                                      int *val_sig_sizes, char *dig, ECDSA_SIG *sig, EC_KEY *eckey, unsigned char *der_sig,
                                      int dealer, int *rec_mult_vals, bool is_first) {

            int len;

            (*hash).reset();
            (*hash).put(val, sizeof(int));
            for(int i = 0; i < round-1; ++i) {
                (*hash).put(val_indices+i, sizeof(int));
                (*hash).put(*(val_signatures+i), *(val_sig_sizes+i));
            }
            (*hash).digest(dig);
            sig = ECDSA_do_sign((unsigned char *)dig, Hash::DIGEST_SIZE, eckey);
            len = i2d_ECDSA_SIG(sig, &der_sig);
            der_sig -= len;
            for(int i = 1; i <= nP; ++i) {
                if(party != i && dealer != i) {
                    if(is_first) send_data(i, rec_mult_vals, sizeof(int));
                    send_data(i, val, sizeof(int));
                    for(int j = 0; j < round-1; ++j) {
                        send_data(i, val_indices+j, sizeof(int));
                        send_data(i, val_sig_sizes+j, sizeof(int));
                        send_data(i, *(val_signatures+j), *(val_sig_sizes+j));
                    }
                    send_data(i, &party, sizeof(int));
                    send_data(i, &len, sizeof(int));
                    send_data(i, der_sig, len);

                }
            }

        }



        int auth_bc(int *ptr, int dealer, EC_KEY *eckey, EC_KEY *pub_keys[nP]) {

            Hash hash;
            Hash rec_hash;

            int val1_indices[nP-1], val2_indices[nP-1];
            int val1_sig_sizes[nP-1], val2_sig_sizes[nP-1];
            unsigned char *val1_signatures[nP-1], *val2_signatures[nP-1];
            int val1, val2;

            recv_data(dealer, &val1, sizeof(int));
            recv_data(dealer, &val1_indices[0], sizeof(int));
            recv_data(dealer, &val1_sig_sizes[0], sizeof(int));

            val1_signatures[0] = (unsigned char *)malloc(val1_sig_sizes[0]);
            recv_data(dealer, val1_signatures[0], val1_sig_sizes[0]);

            bool rec_valid_message;
            int rec_mult_vals = 0;
            bool sigs_valid;
            bool have_two_valid = false;

            int ret;

            std::unordered_set<int> indices;
            std::unordered_set<int> valid_values;

            char dig[Hash::DIGEST_SIZE];
            hash.put(&val1, sizeof(int));
            hash.digest(dig);

            ECDSA_SIG *sig;
            d2i_ECDSA_SIG(&sig, (const unsigned char **)&val1_signatures[0], val1_sig_sizes[0]);
            val1_signatures[0] -= val1_sig_sizes[0];
            rec_valid_message = ECDSA_do_verify((unsigned char *)dig, Hash::DIGEST_SIZE, sig, pub_keys[dealer-1]);
            if(rec_valid_message) {
                valid_values.insert(val1);
                ret = val1;
            }

            int max_sig_size = ECDSA_size(eckey);
            unsigned char *der_sig = (unsigned char *)malloc(max_sig_size * sizeof(unsigned char));
            int len;

            for(int round = 2; round < nP; ++round) {

                if(have_two_valid) {
                    rec_mult_vals = true;
                }
                if(rec_valid_message) {
                    auth_bc_send(&hash, &val1, round, val1_indices, val1_signatures, val1_sig_sizes,
                                 dig, sig, eckey, der_sig, dealer, &rec_mult_vals, true);
                }
                if(have_two_valid) {
                    auth_bc_send(&hash, &val2, round, val2_indices, val2_signatures, val2_sig_sizes,
                                 dig, sig, eckey, der_sig, dealer, &rec_mult_vals, false);
                }

                rec_valid_message = false;
                have_two_valid = false;
                for(int i = 1; i <= nP; ++i) {

                    if(party != i && dealer != i && !have_two_valid) {
                        sigs_valid = true;
                        recv_data(i, &rec_mult_vals, sizeof(int));
                        if(!rec_valid_message) {
                            recv_data(i, &val1, sizeof(int));
                            hash.reset();
                            hash.put(&val1, sizeof(int));
                            rec_hash = hash;
                            rec_hash.digest(dig);
                            for(int j = 0; j < round; ++j) {
                                recv_data(i, &val1_indices[j], sizeof(int));
                                if(indices.size() > 0 && indices.find(val1_indices[j]) != indices.end()) {
                                    sigs_valid = false;
                                }
                                indices.insert(val1_indices[j]);
                                recv_data(i, &val1_sig_sizes[j], sizeof(int));
                                val1_signatures[j] = (unsigned char *)realloc(val1_signatures[j], val1_sig_sizes[j]);
                                recv_data(i, val1_signatures[j], val1_sig_sizes[j]);
                                d2i_ECDSA_SIG(&sig, (const unsigned char **)&val1_signatures[j], val1_sig_sizes[j]);
                                val1_signatures[j] -= val1_sig_sizes[j];
                                sigs_valid = sigs_valid && ECDSA_do_verify((unsigned char *)dig, Hash::DIGEST_SIZE, sig, pub_keys[val1_indices[j]-1]);
                                hash.put(&val1_indices[j], sizeof(int));
                                hash.put(val1_signatures[j], val1_sig_sizes[j]);
                                rec_hash = hash;
                                rec_hash.digest(dig);
                            }
                            if(sigs_valid) {
                                rec_valid_message = true;
                                if(valid_values.size() > 0 && valid_values.find(val1) == valid_values.end()) {
                                    valid_values.insert(val1);
                                    ret = val1;
                                }
                            }

                            indices.clear();

                        } else {
                            recv_data(i, &val2, sizeof(int));

                            if(val2 != val1) {
                                hash.reset();
                                hash.put(&val2, sizeof(int));
                                rec_hash = hash;
                                rec_hash.digest(dig);
                                for(int j = 0; j < round; ++j) {
                                    recv_data(i, &val2_indices[j], sizeof(int));
                                    if(indices.size() > 0 && indices.find(val2_indices[j]) != indices.end()) {
                                        sigs_valid = false;
                                    }
                                    indices.insert(val2_indices[j]);
                                    recv_data(i, &val2_sig_sizes[j], sizeof(int));
                                    val2_signatures[j] = (unsigned char *)realloc(val2_signatures[j], val2_sig_sizes[j]);
                                    recv_data(i, val2_signatures[j], val2_sig_sizes[j]);
                                    d2i_ECDSA_SIG(&sig, (const unsigned char **)&val2_signatures[j], val2_sig_sizes[j]);
                                    val2_signatures[j] -= val2_sig_sizes[j];
                                    sigs_valid = sigs_valid && ECDSA_do_verify((unsigned char *)dig, Hash::DIGEST_SIZE, sig, pub_keys[val2_indices[j]-1]);
                                    hash.put(&val2_indices[j], sizeof(int));
                                    hash.put(val2_signatures[j], val2_sig_sizes[j]);
                                    rec_hash = hash;
                                    rec_hash.digest(dig);
                                }
                                if(sigs_valid) {
                                    have_two_valid = true;
                                    if(valid_values.size() > 0 && valid_values.find(val2) == valid_values.end()) {
                                        valid_values.insert(val2);
                                        ret = val2;
                                    }
                                }

                                indices.clear();

                            } else {
                                for(int j = 0; j < round; ++j) {
                                    recv_data(i, &val2_indices[j], sizeof(int));
                                    recv_data(i, &val2_sig_sizes[j], sizeof(int));
                                    val2_signatures[j] = (unsigned char *)realloc(val2_signatures[j], val2_sig_sizes[j]);
                                    recv_data(i, val2_signatures[j], val2_sig_sizes[j]);
                                }
                            }
                        }

                        if(rec_mult_vals && !have_two_valid) {
                            if(!rec_valid_message) {
                                recv_data(i, &val1, sizeof(int));
                                hash.reset();
                                hash.put(&val1, sizeof(int));
                                rec_hash = hash;
                                rec_hash.digest(dig);
                                for(int j = 0; j < round; ++j) {
                                    recv_data(i, &val1_indices[j], sizeof(int));
                                    if(indices.size() > 0 && indices.find(val1_indices[j]) != indices.end()) {
                                        sigs_valid = false;
                                    }
                                    indices.insert(val1_indices[j]);
                                    recv_data(i, &val1_sig_sizes[j], sizeof(int));
                                    val1_signatures[j] = (unsigned char *)realloc(val1_signatures[j], val1_sig_sizes[j]);
                                    recv_data(i, val1_signatures[j], val1_sig_sizes[j]);
                                    d2i_ECDSA_SIG(&sig, (const unsigned char **)&val1_signatures[j], val1_sig_sizes[j]);
                                    val1_signatures[j] -= val1_sig_sizes[j];
                                    sigs_valid = sigs_valid && ECDSA_do_verify((unsigned char *)dig, Hash::DIGEST_SIZE, sig, pub_keys[val1_indices[j]-1]);
                                    hash.put(&val1_indices[j], sizeof(int));
                                    hash.put(val1_signatures[j], val1_sig_sizes[j]);
                                    rec_hash = hash;
                                    rec_hash.digest(dig);
                                }
                                if(sigs_valid) {
                                    rec_valid_message = true;
                                    if(valid_values.size() > 0 && valid_values.find(val1) == valid_values.end()) {
                                        valid_values.insert(val1);
                                        ret = val1;
                                    }
                                }

                                indices.clear();

                            } else {
                                recv_data(i, &val2, sizeof(int));

                                if(val2 != val1) {
                                    hash.reset();
                                    hash.put(&val2, sizeof(int));
                                    rec_hash = hash;
                                    rec_hash.digest(dig);
                                    for(int j = 0; j < round; ++j) {
                                        recv_data(i, &val2_indices[j], sizeof(int));
                                        if(indices.size() > 0 && indices.find(val2_indices[j]) != indices.end()) {
                                            sigs_valid = false;
                                        }
                                        indices.insert(val2_indices[j]);
                                        recv_data(i, &val2_sig_sizes[j], sizeof(int));
                                        val2_signatures[j] = (unsigned char *)realloc(val2_signatures[j], val2_sig_sizes[j]);
                                        recv_data(i, val2_signatures[j], val2_sig_sizes[j]);
                                        d2i_ECDSA_SIG(&sig, (const unsigned char **)&val2_signatures[j], val2_sig_sizes[j]);
                                        val2_signatures[j] -= val2_sig_sizes[j];
                                        sigs_valid = sigs_valid && ECDSA_do_verify((unsigned char *)dig, Hash::DIGEST_SIZE, sig, pub_keys[val2_indices[j]-1]);
                                        hash.put(&val2_indices[j], sizeof(int));
                                        hash.put(val2_signatures[j], val2_sig_sizes[j]);
                                        rec_hash = hash;
                                        rec_hash.digest(dig);
                                    }
                                    if(sigs_valid) {
                                        have_two_valid = true;
                                        if(valid_values.size() > 0 && valid_values.find(val2) == valid_values.end()) {
                                            valid_values.insert(val2);
                                            ret = val2;
                                        }
                                    }

                                    indices.clear();

                                } else {
                                    for(int j = 0; j < round; ++j) {
                                        recv_data(i, &val2_indices[j], sizeof(int));
                                        recv_data(i, &val2_sig_sizes[j], sizeof(int));
                                        val2_signatures[j] = (unsigned char *)realloc(val2_signatures[j], val2_sig_sizes[j]);
                                        recv_data(i, val2_signatures[j], val2_sig_sizes[j]);
                                    }
                                }
                            }
                        }
                    }
                }

            }

            if(valid_values.size()==0 || valid_values.size()>1) {
                return 0;
            }

            return ret;

        }

        int auth_bc_dealer(int *ptr, EC_KEY *eckey) {

            ECDSA_SIG *sig;
            Hash hash;
            char dig[Hash::DIGEST_SIZE];
            hash.put(ptr, sizeof(int));
            hash.digest(dig);
            sig = ECDSA_do_sign((unsigned char *)dig, Hash::DIGEST_SIZE, eckey);
            if (sig == NULL)
            {
                perror("Could not sign message");
            }

            int max_sig_len = ECDSA_size(eckey);
            unsigned char *der_sig = (unsigned char *)malloc(max_sig_len * sizeof(unsigned char));
            int len = i2d_ECDSA_SIG(sig, &der_sig);
            der_sig -= len;

            for(int i = 1; i <= nP; ++i) {
                if(party != i) {
                    send_data(i, ptr, sizeof(int));
                    send_data(i, &party, sizeof(int));
                    send_data(i, &len, sizeof(int));
                    send_data(i, der_sig, len);
                    flush(i);
                }
            }

            return *ptr;
        }

};
#endif //NETIOMP_H__
