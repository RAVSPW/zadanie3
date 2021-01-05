
import sys

# WAŻNE: Rozmiar bloku MUSI być mniejszy lub równy rozmiarowi klucza!
# Uwaga: rozmiar bloku jest w bajtach, rozmiar klucza w bitach.

DEFAULT_BLOCK_SIZE = 2 # BIERZ PO DWIE LITERY
BYTE_SIZE = 256 # Jeden bajt ma 256 różnych wartości.

def main():
    # Uruchamia test, który szyfruje wiadomość do pliku lub odszyfrowuje wiadomość z pliku.

    filename = 'text.enc' # plik do zapisu / odczytu
    mode = 'decrypt' # ustawione na „szyfrowanie” lub „odszyfrowywanie”

    if mode == 'encrypt':
        message = '''"Tekst ktory ma zostac zaszyfrowany a nastepnie odszyfrowany'''
        pubKeyFilename = 'plik_publickey.txt'
        print('Szyfrowanie i ZAPISYWANIE do %s...' % (filename))
        encryptedText = encryptAndWriteToFile(filename, pubKeyFilename, message)

        
        print('Zaszyfrowany tekst:')
        print(encryptedText)

    elif mode == 'decrypt':
        privKeyFilename = 'plik_privatekey.txt'
        print('Czytanie z %s i odszyfrowanie...' % (filename))
        decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)

        print('ZAPISYWANIE odszyfrowanego tekstu do pliku text.dec...' )
        f = open("text.dec", "w")
        f.write(decryptedText)
        f.close()
        print('Decrypted text:')
        print(decryptedText)


def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    # Konwertuje komunikat w postaci ciągu na listę bloków całkowitych.
    # Każda liczba całkowita reprezentuje 2 ciągi znaków.

    messageBytes = message.encode('ascii') # przekonwertować ciąg na bajty

    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        # Oblicz liczbę całkowitą bloku dla tego bloku tekstu
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts


def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    # Konwertuje listę liczb całkowitych bloku na oryginalny ciąg komunikatu.
    # Oryginalna długość wiadomości jest potrzebna do poprawnej konwersji ostatniej liczby całkowitej bloku.
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Zdekoduj ciąg komunikatu dla 2  znaków z tej liczby całkowitej bloku.
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)


def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Konwertuje ciąg komunikatu na listę liczb całkowitych bloku, a następnie szyfruje każdą liczbę całkowitą bloku.
    # Przekaż klucz PUBLIC do zaszyfrowania.
    encryptedBlocks = []
    n, e = key

    for block in getBlocksFromText(message, blockSize):
        # szyfrogram = tekst jawny ^ e mod n
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks


def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    # Odszyfrowuje listę zaszyfrowanych bloków int do oryginalnego ciągu wiadomości.
    # Oryginalna długość wiadomości jest wymagana do prawidłowego odszyfrowania ostatniego bloku
    # Pamiętaj, aby przekazać klucz PRYWATNY do odszyfrowania.
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        # tekst jawny = tekst zaszyfrowany ^ d mod n
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)


def readKeyFile(keyFilename):
    # Biorąc pod uwagę nazwę pliku, który zawiera klucz publiczny lub prywatny,
    # zwraca klucz jako wartość (n, e) lub (n, d) krotki.
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))


def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    # Używając klucza z pliku kluczy, zaszyfruj wiadomość i zapisz ją w pliku. 
    # Zwraca zaszyfrowany ciąg wiadomości.
    keySize, n, e = readKeyFile(keyFilename)

    # Sprawdź, czy rozmiar klucza jest większy niż rozmiar bloku.
    if keySize < blockSize * 8: # * 8 do konwersji bajtów na bity
        sys.exit('ERROR: Rozmiar bloku to %s bitów, a rozmiar klucza to %s bitów. Szyfr RSA wymaga, aby rozmiar bloku był równy lub większy niż rozmiar klucza. Zmniejsz rozmiar bloku lub użyj innych klawiszy.' % (blockSize * 8, keySize))


    # Zaszyfruj wiadomość
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)

    # Zamień duże wartości int na jedną wartość ciągu.
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)

    # Wypisz zaszyfrowany ciąg do pliku wyjściowego.
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Zwróć także zaszyfrowany ciąg.
    return encryptedContent


def readFromFileAndDecrypt(messageFilename, keyFilename):
    # Używając klucza z pliku klucza, przeczytaj zaszyfrowaną wiadomość z pliku, 
    # a następnie odszyfruj ją. Zwraca odszyfrowany ciąg wiadomości.
    keySize, n, d = readKeyFile(keyFilename)


    # Przeczytaj długość wiadomości i zaszyfrowaną wiadomość z pliku.
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)

    # Sprawdź, czy rozmiar klucza jest większy niż rozmiar bloku.
    if keySize < blockSize * 8: # * 8 konwertować bajty na bity
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or greater than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))

    # Przekonwertuj zaszyfrowaną wiadomość na duże wartości int.
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))

    # Odszyfruj duże wartości int.
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


# Jeśli rsaCipher.py jest uruchomiony (zamiast zaimportowany jako moduł), 
# wywołaj funkcję main ().
if __name__ == '__main__':
    main()
