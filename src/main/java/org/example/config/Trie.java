package org.example.config;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

class TrieNode {
    Map<String, TrieNode> children;

    public TrieNode() {
        children = new HashMap<>();
    }
}
public class Trie {
    private TrieNode root;

    public Trie() {
        root = new TrieNode();
    }

    public void insert(String predecessor, String successor) {
        TrieNode root = getRoot();
        TrieNode curr = search(predecessor, root);
        if (curr == null) {
            System.out.println("Curr is null");
            insert(predecessor);
            curr = getRoot().children.get(predecessor);
        }
        curr.children.put(successor, new TrieNode());
    }

    public void insert(String word) {
        System.out.println("Inserting at top level");
        TrieNode curr = root;
        if (!curr.children.containsKey(word)) {
            curr.children.put(word, new TrieNode());
        }
    }

    // move to source to destination.
    public String getVariableChaining(String target) {
        List<String> variableChaining = new LinkedList<>();
        search(target, getRoot(), variableChaining);
        return variableChaining.toString();
    }

    /*
            n      b
            t      a
            k      c    d


     */

    // n, t, k
    //n , a
    //a, b
    //
/*
      trie.insert("n");
        trie.insert("t");
        trie.insert("k");
        trie.insert("n", "b");
        trie.insert("t", "a");
        trie.insert("k", "c");

        // k->c->d
        trie.insert("c", "d");
 */

    public TrieNode search(String word, TrieNode root) {
        for (String element : root.children.keySet()) {
            if (element.equals(word)) {
                return root.children.get(word);
            }
            TrieNode node =  search(word, root.children.get(element));
            if (node != null) {
                return node;
            }
        }
        return null;
    }


    /*


      */
    public TrieNode search(String target, TrieNode root, List<String> chaining) {
        for (String element : root.children.keySet()) {
            chaining.add(element);
            if (element.equals(target)) {
                return root.children.get(target);
            }
            TrieNode node =  search(target, root.children.get(element), chaining);
            if (node != null) {
                return node;
            }
            chaining.remove(element);
        }
        return null;
    }

    public TrieNode getRoot(){
        return this.root;
    }

    /*
              n      b
              t      a
              k      c    d


k, c,d, f

            n
                b
            t
                a

            k
                c
                    d
                        e

                        f
            m
                n

       */
    public static void main(String[] args) {
        Trie trie = new Trie();
        trie.insert("n");
        trie.insert("t");
        trie.insert("k");
        trie.insert("n", "b");
        trie.insert("t", "a");
        // trie.insert("a", "d");


        trie.insert("k", "c");
        trie.insert("c", "d");
        trie.insert("d", "e");
        trie.insert("d", "f");

        trie.insert("m", "n");
        String varilableChaining = trie.getVariableChaining("f");
        System.out.println(varilableChaining);

    }
}
