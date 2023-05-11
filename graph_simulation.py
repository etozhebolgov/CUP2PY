import networkx as nx
import random
import matplotlib.pyplot as plt
import numpy as np

"""
This script simulates the behaviour of the network interconnected using the created data structure.

Every node on the graph represents a peer, every edge on graph represents that this user can reach a different user directly.
Color of the node represents the percent of nodes reachable by a node in a network.
Closer to red - more peers it can reach using a Search Request.

Simulation:
1) Starts with n_0 nodes (small), not connected to each other.
2) Each of the nodes (all of them) with small probability 'invites new user'; the user is connected to the invited node.
3) Each new user sends update request to its AB (in this model - with constant probability, can be dynamic (Markov Chains?))
4) Adds random connections

Last part of the code graphs wasted_moves/number_of_nodes
"""

n_0 = 5  # number of users at the start
probabilityOfRandomConnectionOfTwoRandomNodes = 0.05
probabilityOfInvite = 0.1
probabilityOfUpdate = 0.5
probabilityOfSuccessConnection = 0.7
standardDepth = 4  # Optimal is unknown
probabilityOfRandomDisconnectedNode = 0.1
wastedMove = 0

i = 100
j = 1

# number of generations: i*j

G = nx.MultiDiGraph()
G.add_nodes_from([i for i in range(n_0)])

def inviteUser(node):
    newNode = len(list(G.nodes()))
    G.add_node(newNode)
    G.add_edge(newNode, node) # newNode -> node
    update(newNode, standardDepth) # ?

def update(nodeSender, depth):
    global wastedMove
    # sends to successor nodes update request and recursion depth
    for neighbour in G.neighbors(nodeSender):
        if random.uniform(0, 1) < probabilityOfSuccessConnection:
            if G.has_edge(neighbour, nodeSender):
                wastedMove += 1
            else:
                G.add_edge(neighbour, nodeSender)
                if depth != 0:
                    update(nodeSender, depth - 1)

def numberOfConnected(node):
    num = 0
    for nodeCheck in G.nodes():
        if nx.has_path(G, node, nodeCheck):
            num += 1

    return num

def colorFromScale(num, maxReach, minReach, totalReach):
    value = (num/totalReach) # smaller - blue, greater - red
    return '#%02x%02x%02x' % (int(value*255), 0, int((1 - value)*255))

def getListWithConnectedNodeNumber(G):
    color_map_num = []
    for node_ in G:
        number_conn = numberOfConnected(node_)
        color_map_num.append(number_conn)
    return color_map_num

def drawGraph(G, color_map_num):
    plt.hist(np.array(color_map_num))

    # plt.savefig(f'{generation}.png') # to save histograms
    plt.show()
    plt.clf()

    color_map = [colorFromScale(number, maxReach, minReach, totalReach) for number in color_map_num]
    nx.draw(G, node_color=color_map, with_labels=True)
    # plt.savefig(f'{generation}.png') # to save graphs
    plt.show()

wasted_moves_list = []
number_of_nodes = []
data = []  # x = number of users from graph, y = number of users they can reach

for i_current in range(i):
    for _ in range(j):
        for node in list(G.nodes()):
            if random.uniform(0, 1) < probabilityOfInvite:
                inviteUser(node)
        for node in list(G.nodes()):
            if random.uniform(0, 1) < probabilityOfUpdate:
                update(node, standardDepth)
        for node in list(G.nodes()):
            if random.uniform(0,1) < probabilityOfRandomConnectionOfTwoRandomNodes:
                randomNode1, randomNode2 = random.choice(list(G.nodes())), random.choice(list(G.nodes()))
                if randomNode1 != randomNode2:
                    G.add_edge(randomNode1, randomNode2)
        if random.uniform(0, 1) < probabilityOfRandomDisconnectedNode:
            G.add_node(len(list(G.nodes())))

    print('Generation: ', (i_current + 1) * j)
    print(G)
    print('Wasted "moves": ' + str(wastedMove))


    color_map_num = getListWithConnectedNodeNumber(G)
    maxReach, minReach, totalReach = max(color_map_num), min(color_map_num), len(G.nodes())
    averageReach = sum(color_map_num) / len(color_map_num)
    print('maximum reach: ' + str(maxReach), '\nminimum reach: ' + str(minReach), '\ntotal nodes: ' + str(totalReach),
          '\naverage reach: ' + str(averageReach) + '\n')

    drawGraph(G, color_map_num)

    wasted_moves_list.append(wastedMove)
    number_of_nodes.append(G.number_of_nodes())

nodesVSwastedMoves = []
for i in range(len(number_of_nodes)):
    nodesVSwastedMoves.append(wasted_moves_list[i]/number_of_nodes[i])
plt.plot(nodesVSwastedMoves)
plt.show()