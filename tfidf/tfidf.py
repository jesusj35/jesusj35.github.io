import numpy as np
from nltk.stem import PorterStemmer
import operator


def loadJSON():
    docs = []
    doc_words = []
    vocab = []
    vocab_dict={}
    cveids=[]
	# open json file and convert to dict
    with open("C:/Users/Marina/Documents/Escuela/Info. Retrieval/jesusj35.github.io/Project1/nvd.json", 'r') as f:
        nvdinfo = json.load(f)
        
    for cve in nvdinfo['CVE_Items']:
        value = cve['cve']['description']['description_data'][0]['value'].lower()
        docs.append(value)
        cveids.append(cve['cve']['CVE_data_meta']['ID'])
    query = "java"
    docs.append(query)  
    doc_words = [doc.split() for doc in docs]
            
   
    vocab= sorted(set(sum(doc_words,[])))
    vocab_dict = {k:i for i,k in enumerate(vocab)}
    return docs, doc_words, vocab, vocab_dict, cveids, query


def create_tfidf():
    X_tf = np.zeros((len(docs), len(vocab)), dtype=int)
    for i, doc in enumerate(doc_words):
        for word in doc:
            X_tf[i,vocab_dict[word]] +=1
    
    idf = np.log10((X_tf.shape[0])/(X_tf.astype(bool).sum(axis=0)))
    X_tfidf = X_tf*idf
    #print(X_tfidf)
    return X_tfidf
	
docs, doc_words, vocab, vocab_dict, cveids, query = loadJSON()
X_tfidf = create_tfidf()
output = open("tfidf.txt", "w")
scores = {}
for i in range(len(X_tfidf)-1):
    scores[cveids[i]] = (np.dot(X_tfidf[i], X_tfidf[-1]))
    
sorted_scores = sorted(scores.items(), key=operator.itemgetter(1), reverse=True)
#scores.sort(reverse=True)
output.write("TFIDF\n")
output.write("QUERY='" + query + "'\n")
for score in sorted_scores:
    output.write(str(score) + "\n")