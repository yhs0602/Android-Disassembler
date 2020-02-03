package com.kyhsgeekcode.disassembler.calc;

import android.util.Log;

import java.util.ArrayList;
import java.util.EmptyStackException;
import java.util.List;
import java.util.Stack;

public class Calculator {
    private static String TAG = "Disassembler calc";

    public static Data Calc(String infix) {
        return CalcPostfix(toPostfix(infix));
    }

    public static Data CalcPostfix(List<Token> postfix) {
        if (postfix.size() == 0)
            return new Data("Please Enter an expression.");
        Log.v(TAG, "postfix=" + postfix.toString());
        Stack<Token> operands = new Stack<>();
        for (Token tok : postfix) {
            if (tok.isOperand()) {
                Log.v(TAG, "tok is operand");
                operands.push(tok);
            } else if (tok.isOperator()) {
                try {
                    Log.v(TAG, "Tok is operator" + tok.toString());
                    Token t = new Token(((Operator) tok).calc(operands));
                    if (t.data != null)
                        operands.push(t);
                    Log.v(TAG, "After op:" + t.toString());
                } catch (EmptyStackException e) {
                    return new Data("Bad expression.");
                }
            }
        }
        return operands.pop().getValue();
    }
    //Time to support unary operator!
    //2019. 01. 29

    public static List<Token> toPostfix(String infix) {
        StringParser sp = new StringParser(infix);
        Stack<Operator> operatorStack = new Stack<>();
        List<Token> postfix = new ArrayList<>();
        Token tok;
        Token prevTok = null;
        while ((tok = sp.getToken()) != null) {
            Log.v(TAG, "Token=(" + tok + ")");
            if (tok.isOperator()) {
                //-,+ are not able to be determined without context.
                if (prevTok == null || prevTok.isOperator()) {
                    //unary?
                    Log.v(TAG, tok + " is unary?");
                    operatorStack.push((Operator) tok);
                } else {
                    if (operatorStack.isEmpty()) {
                        Log.v(TAG, "op stack is empty, pushing " + tok);
                        operatorStack.push((Operator) tok);
                    } else {
                        Operator op1 = operatorStack.peek();
                        if (((Operator) tok).operation == Operator.Operation.LPAR) {
                            operatorStack.push((Operator) tok);
                        } else if (((Operator) tok).operation == Operator.Operation.RPAR) {
                            while (!operatorStack.isEmpty()) {
                                Operator pp = operatorStack.pop();
                                if (pp.operation != Operator.Operation.LPAR)
                                    postfix.add(pp);
                                else
                                    break;
                            }
                        } else {
                            int cmp = op1.compareTo((Operator) tok);
                            if (cmp >= 0)//op1 priority is higher than this token
                            {
                                while (!operatorStack.isEmpty()) {
                                    Operator pp = operatorStack.peek();
                                    if (pp.operation != Operator.Operation.LPAR)
                                        postfix.add(operatorStack.pop());
                                    else
                                        break;
                                }
                                operatorStack.push((Operator) tok);
                            } else// if (cmp < 0) //new token has higher priority
                            {
                                operatorStack.push((Operator) tok);
                            }
                        }
                    }
                }

            } else/* if ( tok.isOperand())*/ {
                postfix.add(tok);
            }
            prevTok = tok;
        }
        while (!operatorStack.isEmpty()) {
            postfix.add(operatorStack.pop());
        }
        return postfix;
    }
}

