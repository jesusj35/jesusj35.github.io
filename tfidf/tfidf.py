from sklearn.feature_extraction.text import TfidfVectorizer 
import json
import pandas as pd

docs=[]

def loadJSON():
	# open json file and convert to dict
    with open("C:/Users/Marina/Documents/Escuela/Info. Retrieval/jesusj35.github.io/Project1/nvd.json", 'r') as f:
        nvdinfo = json.load(f)
        
    for cve in nvdinfo['CVE_Items']:
        value = cve['cve']['description']['description_data'][0]['value']
        docs.append(value)
		


def create_tfidf():
    
	# settings that you use for count vectorizer will go here
    tfidf_vectorizer=TfidfVectorizer(use_idf=True)
    # just send in all your docs here
    tfidf_vectorizer_vectors=tfidf_vectorizer.fit_transform(docs)
    
    # get the first vector out (for the first document)
    first_vector_tfidfvectorizer=tfidf_vectorizer_vectors[0]
 
    # place tf-idf values in a pandas data frame
    df = pd.DataFrame(first_vector_tfidfvectorizer.T.todense(), index=tfidf_vectorizer.get_feature_names(), columns=["tfidf"])
    df = df.sort_values(by=["tfidf"],ascending=False)
    return df
	
loadJSON()
df =create_tfidf()
print(df)
df.to_csv("tfidf.txt")