import numpy as np
import operator
import json
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.pipeline import Pipeline
from sklearn.metrics import pairwise_distances
from sklearn.metrics.pairwise import cosine_similarity

def loadJSON():
    docs = []
    cveids=[]
	# open json file and convert to dict
    with open("C:/Users/Marina/Documents/Escuela/Info. Retrieval/jesusj35.github.io/Project1/nvd.json", 'r') as f:
        nvdinfo = json.load(f)
        
    for cve in nvdinfo['CVE_Items']:
        value = cve['cve']['description']['description_data'][0]['value'].lower()
        docs.append(value)
        cveids.append(cve['cve']['CVE_data_meta']['ID'])
    query = "java"
    #docs.append(query)  
    #doc_words = [doc.split() for doc in docs]
    q = [query]

    return docs, cveids, q
    
def getTfidf():
    tfid = TfidfVectorizer(analyzer='word')
    tfidf_mtrx = tfid.fit_transform(docs)
    vect_tfidf = tfid.transform(q)
    tfidf_dm= pairwise_distances(vect_tfidf, tfidf_mtrx, metric="cosine", n_jobs=-1)
    return tfidf_dm


def getLSI():
    vect = CountVectorizer()
    X = vect.fit_transform(docs)
    lsi = TruncatedSVD(n_components=3,n_iter=10)
    lsi.fit(X)    
    lsi_trans = Pipeline([('tfidf', vect), ('lsi', lsi)])
    lsi_mtrx= lsi_trans.fit_transform(docs)
    vect_lsi = lsi_trans.transform(q)
    lsi_dm = pairwise_distances(vect_lsi, lsi_mtrx, metric='cosine', n_jobs=-1)
    return lsi_dm


#docs, doc_words, vocab, vocab_dict, cveids, query, q = loadJSON()
docs, cveids, q = loadJSON()
#X_tfidf = create_tfidf()
X_tfidf=getTfidf()
output = open("tfidf.txt", "w")
scores = {}
#print(X_tfidf[0][3])
for i in range(len(X_tfidf[0])-1):
    scores[cveids[i]] = X_tfidf[0][i]

sorted_scores = sorted(scores.items(), key=operator.itemgetter(1), reverse=False)
#scores.sort(reverse=True)
output.write("TFIDF\n")
output.write("QUERY='" + q[0] + "'\n")
for score in sorted_scores:
    output.write(str(score) + "\n")
    
lsi_dm = getLSI()
output = open("lsi.txt", "w")
scoresLSI = {}
for i in range(len(lsi_dm[0])-1):
    scoresLSI[cveids[i]] = lsi_dm[0][i]
    
sorted_scoresLSI = sorted(scoresLSI.items(), key=operator.itemgetter(1), reverse=True)
#scores.sort(reverse=True)
output.write("LSI\n")
output.write("QUERY='" + q[0] + "'\n")
for score in sorted_scoresLSI:
    output.write(str(score) + "\n")
cosine = cosine_similarity(X_tfidf, lsi_dm)
print("COSINE SIMILARITY: " + str(cosine))

#print(cosine_similarity(X_tfidf, lsi_dm))