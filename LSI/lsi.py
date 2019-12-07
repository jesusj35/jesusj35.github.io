from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.pipeline import Pipeline
from sklearn.metrics import pairwise_distances
import json
import operator


def loadJSON():
    docs=[]
    cveids=[]
    with open("C:/Users/Marina/Documents/Escuela/Info. Retrieval/jesusj35.github.io/Project1/nvd.json", 'r') as f:
        nvdinfo = json.load(f)
        
    for cve in nvdinfo['CVE_Items']:
        value = cve['cve']['description']['description_data'][0]['value'].lower()
        docs.append(value)
        cveids.append(cve['cve']['CVE_data_meta']['ID'])
    
    q = "java"
    q=[q]
    return docs, cveids, q


def getLSI():
    vect = CountVectorizer()
    X = vect.fit_transform(docs)
    lsi = TruncatedSVD(n_components=3,n_iter=10)
    lsi.fit(X)    
    lsi_trans = Pipeline([('tfidf', vect), ('lsi', lsi)])
    lsi_mtrx= lsi_trans.fit_transform(docs)
    vect_lsi = lsi_trans.transform(query)
    lsi_dm = pairwise_distances(vect_lsi, lsi_mtrx, metric='cosine', n_jobs=-1)
    return lsi_dm

docs, cveids, query = loadJSON()
lsi_dm = getLSI()

output = open("lsi.txt", "w")
scores = {}

j = 0
for i in range(len(lsi_dm[j])):
    scores[cveids[i]] = lsi_dm[0][i]
    j+=1
    
sorted_scores = sorted(scores.items(), key=operator.itemgetter(1), reverse=True)
#scores.sort(reverse=True)
output.write("LSI\n")
output.write("QUERY='" + query[0] + "'\n")
for score in sorted_scores:
    output.write(str(score) + "\n")