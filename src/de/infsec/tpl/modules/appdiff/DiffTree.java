/*
 * Copyright (c) 2015-2017  Erik Derr [derr@cs.uni-saarland.de]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package de.infsec.tpl.modules.appdiff;

import de.infsec.tpl.config.LibScoutConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class DiffTree {
	private static final Logger logger = LoggerFactory.getLogger(DiffTree.class);
	private Node rootNode;

	public enum KIND { BLANK, CHANGE, ADDED, REMOVED }

	public class Node {
		public String name;
		public int changeCount;  // number of changes/additions/removals
		public KIND kind;
		public List<Node> childs;

		private Node() {
			this.changeCount = 0;
			this.kind = KIND.BLANK;
			this.childs = new ArrayList<>();
		}

		public Node(String name) {
			this();
			this.name = name;
		}

		public Node(String name, DiffTree.KIND type) {
			this();
			this.name = name;
			this.kind = type;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof Node))
				return false;
			return ((Node) obj).name.equals(this.name);
		}

		public void print(boolean includeChangeCount) {
			print("", true, includeChangeCount, drawingCharacters.get(LibScoutConfig.PckgTree.useAsciiRendering));
		}

		final Map<Boolean, String[]> drawingCharacters = new HashMap<Boolean, String[]>() {{
			// unicode box-drawing characters ("└── ",  "├── ", "│   ")
			put(false, new String[]{"\u2514\u2500\u2500 ", "\u251C\u2500\u2500 ", "\u2502   "});

			// ascii characters
			put(true , new String[]{"|___ ", "|--- ", "|   "});
		}};

		private void print(String prefix, boolean isTail, boolean includeChangeCount, final String[] charset) {
			logger.info(prefix + (isTail ? charset[0] : charset[1]) + this.toString() + (includeChangeCount && this.changeCount > 0? " (" + this.childs.size() + ")" : ""));

			for (int i = 0; i < childs.size(); i++) {
				childs.get(i).print(prefix + (isTail ? "    " : charset[2]), i == childs.size()-1, includeChangeCount, charset);
			}
		}

		private String kind2String() {
			switch (kind) {
				case ADDED: return " [+] ";
				case CHANGE: return "[<>] ";
				case REMOVED: return " [-] ";
			}

			return "";
		}

	    @Override
	    public String toString() {
	    	return kind2String() + this.name;
	    }

	    public boolean isLeaf() {
	    	return childs.isEmpty();
	    }
	}


	/**
	 * Generate DiffTree
	 * @return {@link DiffTree} instance
	 */
	public static DiffTree make() {
		DiffTree tree = new DiffTree();
		return tree;
	}

	public static DiffTree make(AppDiff diff) {
		DiffTree dtree = new DiffTree();  // TODO verbose?
		diff.packagesAdded.forEach(id -> dtree.update(id, DiffTree.KIND.ADDED));
		diff.packagesRemoved.forEach(id -> dtree.update(id, DiffTree.KIND.REMOVED));

		diff.classesAdded.forEach(id -> dtree.update(id, DiffTree.KIND.ADDED));
		diff.classesRemoved.forEach(id -> dtree.update(id, DiffTree.KIND.REMOVED));

		diff.methodsChanged.forEach(id -> dtree.update(id, DiffTree.KIND.CHANGE));
		diff.methodsRemoved.forEach(id -> dtree.update(id, DiffTree.KIND.REMOVED));
		diff.methodsAdded.forEach(id -> dtree.update(id, DiffTree.KIND.ADDED));
		return dtree;
	}


	private DiffTree() {
		this.rootNode = new Node("Root");
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DiffTree))
			return false;
		
		// compare list of all package names
		DiffTree pt = (DiffTree) obj;
		return new TreeSet<>(pt.getAllPackages()).equals(new TreeSet<>(this.getAllPackages()));
	}
	
	public void print(boolean includeChangeCount) {
		logger.info("Root:");
		
		if (rootNode.childs.size() == 1)
			rootNode.childs.get(0).print(includeChangeCount);
		else
			rootNode.print(includeChangeCount);
	}

	/**
	 * Dump package names that contain at least one class
	 * @return  a mapping from package name to number of included classes
	 */
	public Map<String, Integer> getPackages() {
		return getPackages(rootNode, "", false);
	}
	
	/**
	 * Dump <b>all</b> package names encoded in the tree
	 * @return  an ordered set of package names
	 */
	public Set<String> getAllPackages() {
		return getPackages(rootNode, "", true).keySet();
	}


	private Map<String, Integer> getPackages(Node n, String curPath, boolean dumpAllPackages) {
		TreeMap<String, Integer> res = new TreeMap<String, Integer>();
		
		if (dumpAllPackages)
			res.put(curPath + n.name, n.changeCount);

		if (!n.isLeaf()) {
			for (Node c: n.childs) {
				res.putAll(getPackages(c, curPath + (n.name.equals("Root")? "" : n.name + "."), dumpAllPackages));
			}
		}

		return res;
	}


	public void update(String id, DiffTree.KIND type) {
		List<String> struct = DiffTree.parseIdentifier(id);
		update(struct, type);
	}

	public static List<String> parseIdentifier(String name) {
		String[] struct = name.split("\\.");
		return Arrays.asList(struct);
	}

	private void update(List<String> fragments, DiffTree.KIND type) {
		// update
		Node curNode = rootNode;

		for (int i = 0; i < fragments.size(); i++) {
			Node n = matchChilds(curNode, fragments.get(i));

			if (n != null) {
				curNode = n;
			} else {
				Node newNode = new Node(fragments.get(i), (i == fragments.size()-1? type : KIND.BLANK));
				curNode.childs.add(newNode);
				curNode = newNode;
			}

			if (i == fragments.size()-2) {  // TODO??
				curNode.changeCount++;
			}
		}
	}

	private Node matchChilds(Node n, String str) {
		for (Node node: n.childs) {
			if (node.name.equals(str))
				return node;
		}
		return null;
	}

}
