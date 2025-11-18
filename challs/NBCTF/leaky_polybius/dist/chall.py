import random
import string

SECRET = "????????????????"               
FLAG = "NBCTF{?????????????????????????????}"
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ" 

def generer_grille_aleatoire():
    alphabet_melange = list(ALPHABET)
    random.shuffle(alphabet_melange)
    alphabet_melange = "".join(alphabet_melange)
    
    grille = {}
    positions = {}
    for i, char in enumerate(alphabet_melange):
        ligne = i // 5 + 1
        colonne = i % 5 + 1
        grille[(ligne, colonne)] = char
        positions[char] = f"{ligne}{colonne}"
        
    return alphabet_melange, grille, positions

def chiffrer_message(message, positions):
    coordonnees = ""
    for char in message.upper():
        if char in positions:
            coordonnees += positions[char]
            
    return coordonnees

def calculer_score(proposition, secret):
    score = 0
    for i in range(len(proposition)):
        if i < len(secret) and proposition[i] == secret[i]:
            score += 1
    return score



def main():
    alphabet_secret, _, positions_secretes = generer_grille_aleatoire()
    message_chiffre = chiffrer_message(SECRET, positions_secretes)
    
    print("Welcome to the Polybius Oracle.") 
    print(f"Here is your message to decrypt: {message_chiffre}\n")
    print("Available commands:")
    print("> GUESS <25_letter_alphabet_without_J>")
    print("> SUBMIT <decrypted_password>\n")
    

    while True:
        entree_joueur = input("> ")
        parties = entree_joueur.split()
        if not parties:
            continue
        commande = parties[0].upper()
        
        if commande == "GUESS" and len(parties) > 1:
            proposition_alphabet = parties[1].upper()
            if len(proposition_alphabet) != 25:
                print("Error: The alphabet must contain 25 letters.")
                continue
            
            score = calculer_score(proposition_alphabet, alphabet_secret)
            print(f"Score: {score}/25")
            
            if score == 25:
                print("Congratulations! You found the secret alphabet. You can now decrypt the message.")

        elif commande == "SUBMIT" and len(parties) > 1:
            proposition_mdp = parties[1].upper()
            if proposition_mdp == SECRET:
                print(f"Well done! Here is the flag: {FLAG}")
                break
            else:
                print("Incorrect. Try again.")
        
        else:
            print("Invalid command. Use 'GUESS <alphabet>' or 'SUBMIT <secret>'.")


if __name__ == "__main__":
    main()