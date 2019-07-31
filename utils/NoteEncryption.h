#ifndef NOTE_ENCRYPTION_H_
#define NOTE_ENCRYPTION_H_
#include <string>
template<class T>
T GetRandomness();

class NoteEncryption{
      public:
		NoteEncryption();
	    ~NoteEncryption() {}
		// Gets the ephemeral secret key
		std::string GetEsk(){
			return esk_;
		}

		std::string GetErho();

		// Gets the ephemeral public key
		std::string GetEpk(){
			return epk_;
		}
      private:
		void GetKeypair(unsigned char* priv, unsigned char* pub);
		void GetRandomness(std::string& output, int64_t len);
		void GetRandomness(unsigned char* output, int64_t len);
      private:
		  std::string esk_;
		  std::string epk_;
		  std::string erho_;


};
#endif
