require 'Date'
require 'Time'
require './lib/dictionary'
require './lib/encryptor'
require './lib/decryptor'
require './lib/key_gen'

class Enigma
  attr_reader     :captured_key,
                  :captured_date
  attr_accessor   :cracked_key

  def initialize
    @keygen        = KeyGen.new
    @encryptor     = Encryptor.new
    @decryptor     = Decryptor.new
    @captured_key  = @keygen.random_key
    @captured_date = @keygen.date_string
    @cracked_key   = nil
  end

  def encrypt(message, key = @keygen.key_offset, date = @keygen.date_offset)
    key = @keygen.key_normalizer(key) if key.class == String
    date = @keygen.date_offset(date) if date.class == String
    date = @keygen.date_offset(date.strftime("%d%m%y")) if date.class == Date
    rotation = @keygen.total_rotation(key, date)
    new_message = @encryptor.merge_new_encrypt_values(message, rotation)
    @encryptor.new_encrypt_chars(new_message)
  end

  def decrypt(message, key = @keygen.key_offset, date = @keygen.date_offset)
    key = @keygen.key_normalizer(key) if key.class == String
    date = @keygen.date_offset(date) if date.class == String
    date = @keygen.date_offset(date.strftime("%d%m%y")) if date.class == Date
    rotation = @keygen.total_rotation(key, date)
    new_message = @decryptor.merge_new_decrypt_values(message, rotation)
    @decryptor.new_decrypt_chars(new_message)
  end

  def crack(message, date = @keygen.date_offset)
    check_nums = Array (00001..99999)
    check_nums.each do |number|
      key_offset = @keygen.key_normalizer(number.to_s)
      decrypted_text = decrypt(message, key_offset, date)
      if decrypted_text[-7..-1] == "..end.."
        @cracked_key = number.to_s.rjust(5, "0")
        return decrypted_text
      end
    end
  end
end
