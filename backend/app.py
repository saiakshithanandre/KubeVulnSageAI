from vulnsage.retriever import Retriever
def main():

    rag = Retriever()

    print("="*60)
    print("K8sVulnSage")
    print("="*60)

    while True:

        q = input("\nQuestion: ")

        if q.lower() in ("exit","quit"):
            break

        print()
        print(rag.ask(q))

    rag.close()

if __name__ == "__main__":
    main()